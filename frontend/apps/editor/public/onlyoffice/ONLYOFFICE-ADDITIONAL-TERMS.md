# ONLYOFFICE additional terms

From 9.4, ONLYOFFICE states its additional terms in the `LICENSE` file of
each component (`sdkjs/LICENSE`, `web-apps/LICENSE`, `core/LICENSE`), which
supplement the GNU AGPL version 3 under its Section 7. They require:

1. **Notices and attribution kept:** all copyright notices, licence notices,
   warranty disclaimers, and attribution or origin notices in the program
   are retained (Sections 4, 5 and 7(b)).
2. **Modification notices:** modified versions carry prominent notices that
   they have been modified, with the dates, and that they are based on the
   original ONLYOFFICE software developed by Ascensio System SIA.
3. **Appropriate Legal Notices in the interface:** a clearly accessible,
   prominently visible feature lets users identify ONLYOFFICE as the
   original developer, understand that the version in use may be modified,
   and reach the licence (Section 5).
4. **No trademark licence:** no rights to ONLYOFFICE's trademarks, names,
   logos or branding are granted (Section 7(e)); their use is governed by
   <https://www.onlyoffice.com/trademark-policy>.
5. **Non-code content:** illustrations, icon sets, and technical-writing or
   documentation content are licensed under CC BY-SA 4.0.

The source files keep ONLYOFFICE's copyright headers, including the Section
7(a) exclusion of warranty of non-infringement.

How Kutup meets them:

- the editor and converter are modified versions (by CryptPad and by Kutup);
  each fork's `MODIFICATIONS.md`, included here under `LICENSES/`, lists the
  changes and their dates, and every change is a commit;
- in Kutup's office editor, an **About this editor** button in the header
  identifies ONLYOFFICE and Ascensio System SIA as the original developer,
  states that the version is modified, and links to this licence and to the
  source code. The ONLYOFFICE logo itself is hidden in Kutup's editor: the
  9.4 terms do not require it, and no trademark rights are granted;
- the licence texts, with these additional terms, are under `LICENSES/`.

The pinned corresponding source:

- `kutupbt/onlyoffice-editor` commit
  `42f754df28cadb034ce64c8ca0167c3e048d7e4c` (`sdkjs/LICENSE`,
  `web-apps/LICENSE`, `MODIFICATIONS.md`); and
- `kutupbt/onlyoffice-x2t-wasm` commit
  `7546e7970a212486057529aa2e969984fde0fdf2` (`core/LICENSE`,
  `MODIFICATIONS.md`).

ONLYOFFICE is a trademark of Ascensio System SIA. Kutup does not grant
trademark rights and does not present itself as an official ONLYOFFICE
distribution; it is not affiliated with or endorsed by ONLYOFFICE.
