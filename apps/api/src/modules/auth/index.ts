import { config } from "../../config.js";
import * as secure from "./secure/auth.controller.js";
import * as vulnerable from "./vulnerable/auth.controller.js";
export const authController = config.secureMode ? secure : vulnerable;
