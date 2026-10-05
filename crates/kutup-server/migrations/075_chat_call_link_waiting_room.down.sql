DROP TABLE chat_call_link_knocks;
ALTER TABLE chat_call_links
    DROP CONSTRAINT chat_call_links_waiting_room_needs_host,
    DROP COLUMN host_token_hash,
    DROP COLUMN waiting_room;
