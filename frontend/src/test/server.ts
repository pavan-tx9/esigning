import { setupServer } from "msw/node";

/**
 * The shared mock API. Tests add their own handlers with `server.use(...)`; there are no default
 * handlers, so every call a test allows is visible in that test.
 */
export const server = setupServer();
