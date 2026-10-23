import { randomUUID } from "node:crypto";
import pg from "pg";
import { config } from "./config.js";

const { Pool } = pg;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const connectionString = config.databaseUrl ? new URL(config.databaseUrl) : null;
connectionString?.searchParams.delete("sslmode");
const pool = new Pool({
  connectionString: connectionString?.toString(),
  ssl: { rejectUnauthorized: true },
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error);
});

export async function initializeDatabase() {
  if (!config.databaseUrl) {
    throw new Error("DATABASE_URL must be set before starting the backend.");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS polls (
      id UUID PRIMARY KEY,
      question TEXT NOT NULL,
      created_by TEXT
    );

    CREATE TABLE IF NOT EXISTS poll_options (
      id UUID PRIMARY KEY,
      poll_id UUID NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      position INTEGER NOT NULL,
      votes INTEGER NOT NULL DEFAULT 0 CHECK (votes >= 0)
    );

    CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id UUID NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
      voter_id TEXT NOT NULL,
      option_id UUID NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE,
      PRIMARY KEY (poll_id, voter_id)
    );

    CREATE UNIQUE INDEX IF NOT EXISTS poll_votes_poll_voter_unique
      ON poll_votes (poll_id, voter_id);
  `);
}

export async function createUser(user) {
  const result = await pool.query(
    `INSERT INTO users (id, email, salt, password_hash)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (email) DO NOTHING
     RETURNING id, email, salt, password_hash AS "passwordHash"`,
    [user.id, user.email, user.salt, user.passwordHash],
  );
  return result.rows[0] || null;
}

export async function getUserByEmail(email) {
  const result = await pool.query(
    `SELECT id, email, salt, password_hash AS "passwordHash"
     FROM users WHERE email = $1`,
    [email],
  );
  return result.rows[0] || null;
}

export async function createPoll(poll) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      "INSERT INTO polls (id, question, created_by) VALUES ($1, $2, $3)",
      [poll.id, poll.question, poll.createdBy],
    );

    for (const [position, option] of poll.options.entries()) {
      await client.query(
        "INSERT INTO poll_options (id, poll_id, text, position, votes) VALUES ($1, $2, $3, $4, $5)",
        [option.id, poll.id, option.text, position, option.votes],
      );
    }

    await client.query("COMMIT");
    return poll;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function loadPolls(query, values) {
  const result = await pool.query(
    `SELECT p.id, p.question, p.created_by AS "createdBy",
            o.id AS "optionId", o.text AS "optionText", o.votes
     FROM polls p
     LEFT JOIN poll_options o ON o.poll_id = p.id
     ${query}`,
    values,
  );

  const polls = new Map();
  for (const row of result.rows) {
    let poll = polls.get(row.id);
    if (!poll) {
      poll = { id: row.id, question: row.question, createdBy: row.createdBy, options: [] };
      polls.set(row.id, poll);
    }
    if (row.optionId) {
      poll.options.push({ id: row.optionId, text: row.optionText, votes: row.votes });
    }
  }
  return polls;
}

export async function getPollById(id) {
  if (!uuidPattern.test(id)) return null;
  const polls = await loadPolls("WHERE p.id = $1 ORDER BY o.position", [id]);
  return polls.get(id) || null;
}

export async function hasVotedForPoll(pollId, voterId) {
  if (!uuidPattern.test(pollId)) return false;
  const result = await pool.query(
    "SELECT 1 FROM poll_votes WHERE poll_id = $1 AND voter_id = $2",
    [pollId, voterId],
  );
  return result.rowCount > 0;
}

export async function getPollsByIds(ids) {
  if (!ids.length) return [];
  if (ids.some((id) => !uuidPattern.test(id))) return ids.map(() => null);
  const polls = await loadPolls(
    "WHERE p.id = ANY($1::uuid[]) ORDER BY p.id, o.position",
    [ids],
  );
  return ids.map((id) => polls.get(id) || null);
}

export async function voteForOption(pollId, optionId, voterId) {
  if (!uuidPattern.test(pollId)) {
    return { error: "poll_not_found", message: "Poll not found." };
  }
  if (!uuidPattern.test(optionId)) {
    return { error: "invalid_option", message: "That option does not belong to this poll." };
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const option = await client.query(
      "SELECT 1 FROM poll_options WHERE poll_id = $1 AND id = $2",
      [pollId, optionId],
    );
    if (!option.rowCount) {
      const pollExists = await client.query("SELECT 1 FROM polls WHERE id = $1", [pollId]);
      await client.query("COMMIT");
      return pollExists.rowCount
        ? { error: "invalid_option", message: "That option does not belong to this poll." }
        : { error: "poll_not_found", message: "Poll not found." };
    }

    const recorded = await client.query(
      `INSERT INTO poll_votes (poll_id, voter_id, option_id)
       VALUES ($1, $2, $3)
       ON CONFLICT (poll_id, voter_id) DO NOTHING
       RETURNING poll_id`,
      [pollId, voterId, optionId],
    );
    if (!recorded.rowCount) {
      await client.query("COMMIT");
      return {
        error: "already_voted",
        message: "You have already voted in this poll.",
      };
    }

    await client.query(
      "UPDATE poll_options SET votes = votes + 1 WHERE poll_id = $1 AND id = $2",
      [pollId, optionId],
    );

    const poll = await loadPollsWithClient(client, pollId);
    await client.query("COMMIT");
    return { poll };
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function loadPollsWithClient(client, id) {
  const result = await client.query(
    `SELECT p.id, p.question, p.created_by AS "createdBy",
            o.id AS "optionId", o.text AS "optionText", o.votes
     FROM polls p
     LEFT JOIN poll_options o ON o.poll_id = p.id
     WHERE p.id = $1
     ORDER BY o.position`,
    [id],
  );

  if (!result.rowCount) return null;
  const first = result.rows[0];
  return {
    id: first.id,
    question: first.question,
    createdBy: first.createdBy,
    options: result.rows
      .filter((row) => row.optionId)
      .map((row) => ({ id: row.optionId, text: row.optionText, votes: row.votes })),
  };
}

export function createId() {
  return randomUUID();
}
