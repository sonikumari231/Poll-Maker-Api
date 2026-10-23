export function requireLtiSession(req, res, next) {
  if (!req.session?.ltiUser) {
    return res.status(401).json({
      error: "authentication_required",
      message: "A valid LTI session is required.",
    });
  }

  return next();
}

export function requireUserSession(req, res, next) {
  if (!req.session?.user && !req.session?.ltiUser) {
    return res.status(401).json({
      error: "authentication_required",
      message: "Sign in before creating a poll.",
    });
  }

  return next();
}
