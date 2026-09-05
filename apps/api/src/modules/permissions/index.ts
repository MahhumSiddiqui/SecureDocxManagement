import { config } from "../../config.js";
import * as secure from "./secure/permissions.controller.js";
import * as vulnerable from "./vulnerable/permissions.controller.js";
export const permissionsController = config.secureMode ? secure : vulnerable;
