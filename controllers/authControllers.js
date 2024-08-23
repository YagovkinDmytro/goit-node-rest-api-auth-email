import * as authServices from "../services/authServices.js";
import HttpError from "../helpers/HttpError.js";
import ctrlWrapper from "../decorators/ctrlWrapper.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";

import { getGravatarUrl } from "../helpers/generate-gravatar.js";
import {
  getAvatarPath,
  removeAvatarTemp,
  removeAvatarFile,
} from "../helpers/getAvatarPath.js";

const { JWT_SECRET } = process.env;

const signup = async (req, res) => {
  const { email } = req.body;

  const user = await authServices.findUser({ email });
  if (user) {
    try {
      await removeAvatarTemp(req.file);
    } catch (error) {
      console.log((error.message = "avatar was not accepted"));
    }
    throw HttpError(409, "Email in use");
  }

  const avatarURL = req.file
    ? await getAvatarPath(req.file)
    : getGravatarUrl(email);

  const newUser = await authServices.signup({ ...req.body, avatarURL });

  res.status(201).json({
    user: {
      email: newUser.email,
      subscription: newUser.subscription,
    },
  });
};

const verify = async (req, res) => {
  const { verificationToken } = req.params;
  const user = await authServices.findUser({ verificationToken });
  if (!user) {
    throw HttpError(404, "User not found or already verified");
  }

  await authServices.updateUser(
    { verificationToken },
    { verify: true, verificationToken: null }
  );
  res.json({
    message: "Verification successful",
  });
};

const signin = async (req, res) => {
  const { email, password } = req.body;
  const user = await authServices.findUser({ email });
  if (!user) {
    throw HttpError(401, "Email or password is wrong");
  }
  if (!user.verify) {
    throw HttpError(401, "Email not verify");
  }
  const passwordCompare = await bcrypt.compare(password, user.password);
  if (!passwordCompare) {
    throw HttpError(401, "Email or password is wrong");
  }

  const { id } = user;

  const payload = {
    id,
  };

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "24h" });

  await authServices.updateUser({ id }, { token });

  res.json({
    token,
    user: {
      email: user.email,
      subscription: user.subscription,
    },
  });
};

const logout = async (req, res) => {
  const { id } = req.user;
  await authServices.updateUser({ id }, { token: null });

  res.status(204).json();
};

const getCurrent = async (req, res) => {
  const { email, subscription } = req.user;

  res.json({
    user: {
      email,
      subscription,
    },
  });
};

const setSubscription = async (req, res) => {
  const { id } = req.user;
  const data = req.body;
  const { email, subscription } = await authServices.updateUser({ id }, data);

  res.json({
    user: {
      email,
      subscription,
    },
  });
};

const addAvatar = async (req, res) => {
  const { id, avatarURL: oldPath } = req.user;
  const avatarExtention = oldPath.split(".").pop();

  if (avatarExtention === "jpg") {
    try {
      await removeAvatarFile(oldPath);
    } catch (error) {
      console.log(error.message);
    }
  }

  const avatarURL = await getAvatarPath(req.file);

  const { avatarURL: newAvatarURL } = await authServices.updateUser(
    { id },
    { avatarURL }
  );

  res.json({
    user: {
      avatarURL: newAvatarURL,
    },
  });
};

export default {
  signup: ctrlWrapper(signup),
  verify: ctrlWrapper(verify),
  signin: ctrlWrapper(signin),
  logout: ctrlWrapper(logout),
  getCurrent: ctrlWrapper(getCurrent),
  setSubscription: ctrlWrapper(setSubscription),
  addAvatar: ctrlWrapper(addAvatar),
};
