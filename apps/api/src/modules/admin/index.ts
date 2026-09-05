import { config } from "../../config.js";
import * as secure from "./secure/admin.controller.js";
import * as vulnerable from "./vulnerable/admin.controller.js";
export const adminController = config.secureMode ? secure : vulnerable;
