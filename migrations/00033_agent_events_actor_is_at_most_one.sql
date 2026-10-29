

ALTER TABLE agent_events DROP CONSTRAINT agent_events_actor_is_whole;

ALTER TABLE agent_events ADD CONSTRAINT agent_events_actor_is_whole
    CHECK (actor_user_id IS NULL OR actor_token_id IS NULL);


ALTER TABLE agent_events DROP CONSTRAINT agent_events_actor_is_whole;

ALTER TABLE agent_events ADD CONSTRAINT agent_events_actor_is_whole
    CHECK ((actor_user_id IS NULL) = (actor_token_id IS NULL));
