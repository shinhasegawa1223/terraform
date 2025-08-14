// Client-side only
import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
  CognitoUserSession,
} from "amazon-cognito-identity-js";
import { decodeJwtPayload } from "@/lib/jwt";

const userPool = new CognitoUserPool({
  UserPoolId: process.env.NEXT_PUBLIC_COGNITO_USER_POOL_ID!,
  ClientId: process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID!,
});

export type SignInResult = {
  accessToken: string;
  idToken: string;
  refreshToken?: string;
  tenantId?: string | null;
  idClaims: any;
};

export function signInWithEmailPassword(email: string, password: string): Promise<SignInResult> {
  return new Promise((resolve, reject) => {
    const user = new CognitoUser({ Username: email, Pool: userPool });
    const auth = new AuthenticationDetails({ Username: email, Password: password });

    user.authenticateUser(auth, {
      onSuccess: (session: CognitoUserSession) => {
        const accessToken = session.getAccessToken().getJwtToken();
        const idToken = session.getIdToken().getJwtToken();
        const refreshToken = session.getRefreshToken()?.getToken();
        const idClaims = decodeJwtPayload(idToken);
        const tenantId = idClaims["custom:tenant_id"] ?? idClaims["tenant_id"] ?? null;
        resolve({ accessToken, idToken, refreshToken, tenantId, idClaims });
      },
      onFailure: (err) => reject(err),
      newPasswordRequired: (_userAttributes, _requiredAttributes) => {
        reject({ challenge: "NEW_PASSWORD_REQUIRED", user });
      },
      mfaRequired: () => {
        reject({ message: "MFA is not supported in this flow" });
      },
    });
  });
}

export function completeNewPassword(user: CognitoUser, newPassword: string): Promise<SignInResult> {
  return new Promise((resolve, reject) => {
    user.completeNewPasswordChallenge(newPassword, {}, {
      onSuccess: (session: CognitoUserSession) => {
        const accessToken = session.getAccessToken().getJwtToken();
        const idToken = session.getIdToken().getJwtToken();
        const refreshToken = session.getRefreshToken()?.getToken();
        const idClaims = decodeJwtPayload(idToken);
        const tenantId = idClaims["custom:tenant_id"] ?? idClaims["tenant_id"] ?? null;
        resolve({ accessToken, idToken, refreshToken, tenantId, idClaims });
      },
      onFailure: (err) => reject(err),
    });
  });
}
