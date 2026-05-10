package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var devicesCmd = &cobra.Command{
	Use:   "devices",
	Short: "List and revoke devices on your account",
}

var devicesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List devices registered for your account",
	Args:  cobra.NoArgs,
	RunE:  runDevicesList,
}

var (
	devicesRevokeYes bool
)

var devicesRevokeCmd = &cobra.Command{
	Use:   "revoke <device-id>",
	Short: "Revoke a device (closes any in-flight WebSocket sessions for it)",
	Args:  cobra.ExactArgs(1),
	RunE:  runDevicesRevoke,
}

func init() {
	devicesRevokeCmd.Flags().BoolVar(&devicesRevokeYes, "yes", false,
		"skip the confirmation prompt")

	devicesCmd.AddCommand(devicesListCmd)
	devicesCmd.AddCommand(devicesRevokeCmd)
}

func runDevicesList(_ *cobra.Command, _ []string) error {
	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	devices, err := client.ListUserDevices()
	if err != nil {
		return err
	}
	if jsonOut {
		out, _ := json.Marshal(devices)
		fmt.Println(string(out))
		return nil
	}
	if len(devices) == 0 {
		fmt.Println("(no devices registered)")
		return nil
	}
	fmt.Printf("%-12s  %-30s  %-20s  %-20s  %s\n", "ID", "LABEL", "CREATED", "LAST SEEN", "STATUS")
	for _, d := range devices {
		last := "(never)"
		if d.LastSeenAt != nil {
			last = d.LastSeenAt.Local().Format(time.RFC3339)
		}
		status := "active"
		if !d.IsActive {
			status = "revoked"
		}
		fmt.Printf("%-12d  %-30s  %-20s  %-20s  %s\n",
			d.DeviceID, d.Label, d.CreatedAt.Local().Format(time.RFC3339), last, status)
	}
	return nil
}

func runDevicesRevoke(_ *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		return fmt.Errorf("device-id must be a number, got %q", args[0])
	}

	client, _, cleanup, err := requireSessionFull()
	if err != nil {
		return err
	}
	defer cleanup()

	if !devicesRevokeYes {
		// Destructive: closes any in-flight WS sessions signed by this
		// device's key (server-side WithRevokeHook in main.go).
		fmt.Fprintf(os.Stderr,
			"Revoke device %d? This closes its active sessions. [y/N]: ", id)
		reader := bufio.NewReader(os.Stdin)
		ans, _ := reader.ReadString('\n')
		ans = strings.ToLower(strings.TrimSpace(ans))
		if ans != "y" && ans != "yes" {
			return fmt.Errorf("aborted")
		}
	}

	if err := client.RevokeUserDevice(id); err != nil {
		return err
	}
	if jsonOut {
		fmt.Printf(`{"deviceId":%d,"revoked":true}`+"\n", id)
	} else {
		fmt.Printf("Revoked device %d\n", id)
	}
	return nil
}
