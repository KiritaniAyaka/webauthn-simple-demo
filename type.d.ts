export {}

type User = ({
	device: ({
			transports: {
					id: number;
					type: string;
					deviceId: number | null;
			}[];
	} & {
			id: number;
			credentialPublicKey: string;
			credentialID: string;
			counter: number;
			userId: number;
	})[];
} & {
	id: number;
	username: string;
}) | null

declare module 'express-session' {
  interface SessionData {
    /**
     * A simple way of storing a user's current challenge being signed by registration or authentication.
     * It should be expired after `timeout` milliseconds (optional argument for `generate` methods,
     * defaults to 60000ms)
     */
    challenge?: string;
		user?: User
		username?: string
		loggedUserId?: number
  }
}