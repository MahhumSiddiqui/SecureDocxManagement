import { config } from "../../config.js";
import * as secure from "./secure/documents.controller.js";
import * as vulnerable from "./vulnerable/documents.controller.js";
export const documentsController = config.secureMode ? secure : vulnerable;
