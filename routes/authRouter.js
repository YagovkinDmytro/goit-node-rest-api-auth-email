import { Router } from "express";
import authControllers from "../controllers/authControllers.js";
import validateBody from "../decorators/validateBody.js";
import {
  authSetSubscriptionSchema,
  authSignupSchema,
} from "../schemas/authSchemas.js";
import authenticate from "../middlewares/authenticate.js";
import uploadMiddleware from "../middlewares/upload.js";

const signupMiddleware = validateBody(authSignupSchema);
const setSubscriptionMidellware = validateBody(authSetSubscriptionSchema);

const authRouter = Router();

authRouter.post(
  "/register",
  uploadMiddleware,
  signupMiddleware,
  authControllers.signup
);
authRouter.post("/login", signupMiddleware, authControllers.signin);
authRouter.post("/logout", authenticate, authControllers.logout);
authRouter.get("/current", authenticate, authControllers.getCurrent);
authRouter.patch(
  "/subscription",
  authenticate,
  setSubscriptionMidellware,
  authControllers.setSubscription
);

authRouter.patch(
  "/avatars",
  uploadMiddleware,
  authenticate,
  authControllers.addAvatar
);

export default authRouter;
