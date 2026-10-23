import express from "express";
import { requireUserSession } from "../auth/session.js";
import { createId, createPoll, getPollById, voteForOption } from "../storage.js";

const router = express.Router();

function presentPoll(poll) {
  return {
    id: poll.id,
    question: poll.question,
    options: poll.options.map(({ id, text, votes }) => ({ id, text, votes })),
  };
}

router.post("/", requireUserSession, async (req, res, next) => {
  const question = typeof req.body?.question === "string" ? req.body.question.trim() : "";
  const options = Array.isArray(req.body?.options)
    ? req.body.options.map((option) => typeof option === "string" ? option.trim() : "")
    : [];

  if (!question || options.length < 2 || options.some((option) => !option)) {
    return res.status(400).json({
      error: "invalid_poll",
      message: "A question and at least two non-empty options are required.",
    });
  }

  try {
    const poll = {
      id: createId(),
      question,
      options: options.map((text) => ({ id: createId(), text, votes: 0 })),
      createdBy: req.session.user?.id || req.session.ltiUser?.userId || null,
    };
    await createPoll(poll);
    return res.status(201).json(presentPoll(poll));
  } catch (error) {
    return next(error);
  }
});

router.get("/:id", async (req, res, next) => {
  try {
    const poll = await getPollById(req.params.id);
    if (!poll) {
      return res.status(404).json({ error: "poll_not_found", message: "Poll not found." });
    }
    return res.json(presentPoll(poll));
  } catch (error) {
    return next(error);
  }
});

router.post("/:id/vote", async (req, res, next) => {
  const optionId = req.body?.optionId;
  if (typeof optionId !== "string" || !optionId) {
    return res.status(400).json({ error: "invalid_vote", message: "Select an option to vote." });
  }

  try {
    const result = await voteForOption(req.params.id, optionId);
    if (result.error) {
      return res.status(result.error === "poll_not_found" ? 404 : 400).json({
        error: result.error,
        message: result.message,
      });
    }
    return res.json(presentPoll(result.poll));
  } catch (error) {
    return next(error);
  }
});

export default router;
