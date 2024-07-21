//
// Copyright 2017-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.
// A copy of the License is located at
//
// http://aws.amazon.com/apache2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
//

import Foundation

extension AWSMobileClient {
    
    internal convenience init(setDelegate: Bool) {
        self.init()
        if (setDelegate) {
            UserPoolOperationsHandler.sharedInstance.authHelperDelegate = self
        }
    }
    
    internal var userPoolClient: AWSCognitoIdentityUserPool? {
        return self.userpoolOpsHelper?.userpoolClient
    }
    
    internal var currentUser: AWSCognitoIdentityUser? {
        return self.userPoolClient?.currentUser()
    }

    /// Returns the username attribute of the access token for the current logged in user,  nil otherwise.
    /// Note that the value stored may vary depending on how sign-in was performed.
    /// @see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html#amazon-cognito-user-pools-using-the-access-token
    public var username: String? {
        return self.userpoolOpsHelper?.currentActiveUser?.username
    }

    public var userSub: String? {
        guard  (isSignedIn && (federationProvider == .hostedUI || federationProvider == .userPools)) else {
            return nil
        }

        guard let idToken = self.cachedLoginsMap.first?.value else {
            return nil
        }
        let sessionToken = SessionToken(tokenString: idToken)
        guard let sub = sessionToken.claims?["sub"] as? String else {
            return nil
        }
        return sub
    }

    /// The identity id associated with this provider. This value will be fetched from the keychain at startup. If you do not want to reuse the existing identity id, you must call the clearKeychain method. If the identityId is not fetched yet, it will return nil. Use `getIdentityId()` method to force a server fetch when identityId is not available.
    override public var identityId: String? {
        return self.internalCredentialsProvider?.identityId
    }

    /// Returns true if there is a user currently signed in.
    @objc public var isSignedIn: Bool {
        get {
            return self.cachedLoginsMap.count > 0
        }
    }

    public func handleAuthResponse(_ application: UIApplication, open url: URL, sourceApplication: String?, annotation: Any) {
        if (isCognitoAuthRegistered) {
            AWSCognitoAuth.init(forKey: AWSMobileClientConstants.CognitoAuthRegistrationKey).application(application, open: url, options: [:])
        }
    }

    /// Fetches the `AWSCredentials` asynchronously.
    ///
    /// - Parameter completionHandler: completionHandler which would have `AWSCredentials` if successfully retrieved, else error.
    public func getAWSCredentials(_ completionHandler: @escaping(AWSCredentials?, Error?) -> Void) {
        if self.internalCredentialsProvider == nil {
            completionHandler(nil, AWSMobileClientError.cognitoIdentityPoolNotConfigured(message: "There is no valid cognito identity pool configured in `awsconfiguration.json`."))
        }
        
        let cancellationToken = self.credentialsFetchCancellationSource
        credentialsFetchOperationQueue.addOperation {
            self.credentialsFetchLock.enter()
            self.internalCredentialsProvider?.credentials(withCancellationToken: cancellationToken).continueWith(block: { (task) -> Any? in
                // If we have called cancellation already, leave the block without doing anything
                // with the fetched credentials.
                if (task.isCancelled || cancellationToken.isCancellationRequested) {
                    self.credentialsFetchLock.leave()
                    completionHandler(task.result, task.error)
                    return nil
                }
                
                if let error = task.error {
                    if error._domain == AWSCognitoIdentityErrorDomain
                        && error._code == AWSCognitoIdentityErrorType.notAuthorized.rawValue
                        && self.federationProvider == .none {
                        
                        self.credentialsFetchLock.leave()
                        completionHandler(nil, AWSMobileClientError.guestAccessNotAllowed(message: "Your backend is not configured with cognito identity pool to allow guest acess. Please allow un-authenticated access to identity pool to use this feature."))
                        
                    } else if error._domain == AWSCognitoIdentityErrorDomain
                        && error._code == AWSCognitoIdentityErrorType.notAuthorized.rawValue
                        && self.federationProvider == .oidcFederation {
                        // store a reference to the completion handler which we would be calling later on.
                        self.pendingAWSCredentialsCompletion = completionHandler
                        
                        self.mobileClientStatusChanged(userState: .signedOutFederatedTokensInvalid, additionalInfo: [self.ProviderKey:self.cachedLoginsMap.first!.key])
                    } else {
                        self.credentialsFetchLock.leave()
                        completionHandler(nil, error)
                    }
                } else if let result = task.result {
                    if(self.federationProvider == .none && self.currentUserState != .guest) {
                        self.mobileClientStatusChanged(userState: .guest, additionalInfo: [:])
                    }
                    self.credentialsFetchLock.leave()
                    completionHandler(result, nil)
                }
                
                return nil
            })
            self.credentialsFetchLock.wait()
        }
    }

    /// Invoke this function to release any sign-in waits.
    /// When you receive a notifcation which is `signedOutFederatedTokensInvalid` or `signedOutUserPoolsTokensInvalid` you need to proovide SDK the token via `federate` method or call the `signIn` method and complete the sign-in flow. If you can't get the latest token from the user, you can call this method to un-block any waiting calls.
    public func releaseSignInWait() {
        if self.federationProvider == .userPools {
            self.userpoolOpsHelper.passwordAuthTaskCompletionSource?.set(error: AWSMobileClientError.unableToSignIn(message: "Unable to get valid sign in session from the end user."))
            self.userpoolOpsHelper.passwordAuthTaskCompletionSource = nil
            self.userpoolOpsHelper.customAuthChallengeTaskCompletionSource?.set(error: AWSMobileClientError.unableToSignIn(message: "Unable to get valid sign in session from the end user."))
            self.userpoolOpsHelper.customAuthChallengeTaskCompletionSource = nil
        } else if self.federationProvider == .hostedUI {
            self.pendingGetTokensCompletion?(nil, AWSMobileClientError.unableToSignIn(message: "Could not get valid token from the user."))
            self.pendingGetTokensCompletion = nil
            self.tokenFetchLock.leave()
        } else if self.federationProvider == .oidcFederation {
            self.pendingAWSCredentialsCompletion?(nil, AWSMobileClientError.unableToSignIn(message: "Could not get valid federation token from the user."))
            self.pendingAWSCredentialsCompletion = nil
            self.credentialsFetchLock.leave()
        }
    }

    /// Returns cached UserPools auth JWT tokens if valid.
    /// If the `idToken` is not valid, and a refresh token is available, refresh token is used to get a new `idToken`.
    /// If there is no refresh token and the user is signed in, a notification is dispatched to indicate requirement of user to re-signin.
    /// The call to wait will be synchronized so that if multiple threads call this method, they will block till the first thread gets the token.
    ///
    /// - Parameter completionHandler: Tokens if available, else error.
    public func getTokens(_ completionHandler: @escaping (Tokens?, Error?) -> Void) {
        switch self.federationProvider {
        case .userPools, .hostedUI:
            break
        default:
            completionHandler(nil, AWSMobileClientError.notSignedIn(message: notSignedInErrorMessage))
            return
        }
        
        if self.federationProvider == .hostedUI {
            self.tokenFetchOperationQueue.addOperation {
                self.tokenFetchLock.enter()
                AWSCognitoAuth.init(forKey: self.CognitoAuthRegistrationKey).getSession({ (session, error) in

                    if let sessionError = error,
                        (sessionError as NSError).domain == AWSCognitoAuthErrorDomain,
                        let errorType = AWSCognitoAuthClientErrorType(rawValue: (sessionError as NSError).code),
                        (errorType == .errorExpiredRefreshToken) {
                        self.pendingGetTokensCompletion = completionHandler
                        self.mobileClientStatusChanged(userState: .signedOutUserPoolsTokenInvalid,
                                                       additionalInfo: [self.ProviderKey:"OAuth"])
                        // return early without releasing the tokenFetch lock.
                        return
                    } else if let session = session {
                        completionHandler(self.getTokensForCognitoAuthSession(session: session), nil)
                    } else {
                        completionHandler(nil, error)
                    }
                    self.tokenFetchLock.leave()
                })
                self.tokenFetchLock.wait()
            }
            return
        }
        if self.federationProvider == .userPools {
            self.userpoolOpsHelper.userpoolClient?.delegate = self.userpoolOpsHelper
            self.userpoolOpsHelper.authHelperDelegate = self
            self.tokenFetchOperationQueue.addOperation {
                self.tokenFetchLock.enter()
                self.currentUser?.getSession().continueWith(block: { (task) -> Any? in
                    if let error = task.error {
                        completionHandler(nil, error)
                        self.invokeSignInCallback(signResult: nil, error: error)
                    } else if let session = task.result {
                        completionHandler(self.userSessionToTokens(userSession: session), nil)
                        self.federationProvider = .userPools
                        if (self.currentUserState != .signedIn) {
                            self.mobileClientStatusChanged(userState: .signedIn, additionalInfo: [:])
                        }
                        self.invokeSignInCallback(signResult: SignInResult(signInState: .signedIn), error: nil)
                    }
                    self.tokenFetchLock.leave()
                    return nil
                })
                self.tokenFetchLock.wait()
            }
            return
        }
    }

    internal func userSessionToTokens(userSession: AWSCognitoIdentityUserSession) -> Tokens {
        var idToken: SessionToken?
        var accessToken: SessionToken?
        var refreshToken: SessionToken?
        if userSession.idToken != nil {
            idToken = SessionToken(tokenString: userSession.idToken?.tokenString)
        }
        if userSession.accessToken != nil {
            accessToken = SessionToken(tokenString: userSession.accessToken?.tokenString)
        }
        if userSession.refreshToken != nil {
            refreshToken = SessionToken(tokenString: userSession.refreshToken?.tokenString)
        }
        return Tokens(idToken: idToken, accessToken: accessToken, refreshToken: refreshToken, expiration: userSession.expirationTime)
    }

}

//MARK: Extension to hold user attribute operations
extension AWSMobileClient {

    var notSignedInErrorMessage: String {
        return "User is not signed in to Cognito User Pool, please sign in to use this API."
    }

    /// Verify a user attribute like phone_number.
    ///
    /// This method is only valid for users signed in via UserPools (either directly or via HostedUI).
    ///
    /// - Parameters:
    ///   - attributeName: name of the attribute.
    ///   - clientMetaData: A map of custom key-value pairs that you can provide as input for any
    ///   custom workflows that this action triggers.
    ///   - completionHandler: completionHandler which will be called when the result is avilable.
    public func verifyUserAttribute(attributeName: String,
                                    clientMetaData: [String:String] = [:],
                                    completionHandler: @escaping ((UserCodeDeliveryDetails?, Error?) -> Void)) {
        guard self.federationProvider == .userPools || self.federationProvider == .hostedUI else {
            completionHandler(nil, AWSMobileClientError.notSignedIn(message: notSignedInErrorMessage))
            return
        }
        let userDetails = AWSMobileClientUserDetails(with: self.userpoolOpsHelper.currentActiveUser!)
        userDetails.verifyUserAttribute(attributeName: attributeName, clientMetaData: clientMetaData, completionHandler: completionHandler)
    }
    
    /// Update the attributes for a user.
    ///
    /// This method is only valid for users signed in via UserPools (either directly or via HostedUI).
    ///
    /// - Parameters:
    ///   - attributeMap: the attribute map of the user.
    ///   - clientMetaData: A map of custom key-value pairs that you can provide as input for any
    ///   custom workflows that this action triggers.
    ///   - completionHandler: completionHandler which will be called when the result is avilable.
    public func updateUserAttributes(attributeMap: [String: String],
                                     clientMetaData: [String:String] = [:],
                                     completionHandler: @escaping (([UserCodeDeliveryDetails]?, Error?) -> Void)) {
        guard self.federationProvider == .userPools || self.federationProvider == .hostedUI else {
            completionHandler(nil, AWSMobileClientError.notSignedIn(message: notSignedInErrorMessage))
            return
        }
        let userDetails = AWSMobileClientUserDetails(with: self.userpoolOpsHelper.currentActiveUser!)
        userDetails.updateUserAttributes(attributeMap: attributeMap, clientMetaData: clientMetaData, completionHandler: completionHandler)
    }
    
    /// Fetches the attributes for logged in user.
    ///
    /// This method is only valid for users signed in via UserPools (either directly or via HostedUI).
    ///
    /// - Parameter completionHandler: completion handler which will be invoked when result is available.
    public func getUserAttributes(completionHandler: @escaping (([String: String]?, Error?) -> Void)) {
        guard self.federationProvider == .userPools || self.federationProvider == .hostedUI else {
            completionHandler(nil, AWSMobileClientError.notSignedIn(message: notSignedInErrorMessage))
            return
        }
        let userDetails = AWSMobileClientUserDetails(with: self.userpoolOpsHelper.currentActiveUser!)
        userDetails.getUserAttributes(completionHandler: completionHandler)
    }
    
    /// Confirm the updated attributes using a confirmation code.
    ///
    /// This method is only valid for users signed in via UserPools (either directly or via HostedUI).
    ///
    /// - Parameters:
    ///   - attributeName: the attribute to be confirmed.
    ///   - code: the code sent to the user.
    ///   - completionHandler: completionHandler which will be called when the result is avilable.
    public func confirmUpdateUserAttributes(attributeName: String, code: String, completionHandler: @escaping ((Error?) -> Void)) {
        guard self.federationProvider == .userPools || self.federationProvider == .hostedUI else {
            completionHandler(AWSMobileClientError.notSignedIn(message: notSignedInErrorMessage))
            return
        }
        self.confirmVerifyUserAttribute(attributeName: attributeName, code: code, completionHandler: completionHandler)
    }
    
    /// Confirm the attribute using a confirmation code.
    ///
    /// This method is only valid for users signed in via UserPools (either directly or via HostedUI).
    ///
    /// - Parameters:
    ///   - attributeName: the attribute to be verified.
    ///   - code: the code sent to the user.
    ///   - completionHandler: completionHandler which will be called when the result is avilable.
    public func confirmVerifyUserAttribute(attributeName: String, code: String, completionHandler: @escaping ((Error?) -> Void)) {
        guard self.federationProvider == .userPools || self.federationProvider == .hostedUI else {
            completionHandler(AWSMobileClientError.notSignedIn(message: notSignedInErrorMessage))
            return
        }
        let userDetails = AWSMobileClientUserDetails(with: self.userpoolOpsHelper.currentActiveUser!)
        userDetails.confirmVerifyUserAttribute(attributeName: attributeName,
                                               code: code,
                                               completionHandler: completionHandler)
    }
}

//MARK: Extension to hold UserPoolAuthHelperlCallbacks methods
extension AWSMobileClient: UserPoolAuthHelperlCallbacks {
    
    func getPasswordDetails(_ authenticationInput: AWSCognitoIdentityPasswordAuthenticationInput,
                            passwordAuthenticationCompletionSource: AWSTaskCompletionSource<AWSCognitoIdentityPasswordAuthenticationDetails>) {
        
        // getPasswordDetails for customAuth will be called when the session expires.
        // This call would be triggered from getSession(). In this case we donot need
        // to inform the user that the session is expired, because that is handled by
        // getCustomAuthenticationDetails.
        if(self.userPoolClient?.isCustomAuth ?? false) {
            let authDetails = AWSCognitoIdentityPasswordAuthenticationDetails(username: self.currentUser?.username ?? "",
                                                                              password: userPassword ?? "dummyPassword")
            passwordAuthenticationCompletionSource.set(result: authDetails)
            userPassword = nil
            return
        }
        if (self.federationProvider != .userPools) {
            passwordAuthenticationCompletionSource.set(error: AWSMobileClientError.notSignedIn(message: notSignedInErrorMessage))
        }
        switch self.currentUserState {
        case .signedIn, .signedOutUserPoolsTokenInvalid:
            self.userpoolOpsHelper.passwordAuthTaskCompletionSource = passwordAuthenticationCompletionSource
            self.mobileClientStatusChanged(userState: .signedOutUserPoolsTokenInvalid, additionalInfo: ["username":self.userPoolClient?.currentUser()?.username ?? ""])
        default:
            break
        }
    }
    
    func didCompletePasswordStepWithError(_ error: Error?) {
        if let error = error {
            invokeSignInCallback(signResult: nil, error: AWSMobileClientError.makeMobileClientError(from: error))
        }
    }
    
    func getNewPasswordDetails(_ newPasswordRequiredInput: AWSCognitoIdentityNewPasswordRequiredInput,
                               newPasswordRequiredCompletionSource: AWSTaskCompletionSource<AWSCognitoIdentityNewPasswordRequiredDetails>) {
        self.userpoolOpsHelper.newPasswordRequiredTaskCompletionSource = newPasswordRequiredCompletionSource
        let result = SignInResult(signInState: .newPasswordRequired, codeDetails: nil)
        invokeSignInCallback(signResult: result, error: nil)
    }
    
    func didCompleteNewPasswordStepWithError(_ error: Error?) {
        if let error = error {
            invokeSignInCallback(signResult: nil, error: AWSMobileClientError.makeMobileClientError(from: error))
        }
    }
    
    func getCustomAuthenticationDetails(_ customAuthenticationInput: AWSCognitoIdentityCustomAuthenticationInput,
                                        customAuthCompletionSource: AWSTaskCompletionSource<AWSCognitoIdentityCustomChallengeDetails>) {
        
        self.userpoolOpsHelper.customAuthChallengeTaskCompletionSource = customAuthCompletionSource
        
        // getCustomAuthenticationDetails will be invoked in a signIn process or when the token expires.
        // If this get invoked when the token expires, we first inform the listener that the user got signedOut. This
        // delegate is called in token expiry if the user state is .signedIn or .signedOutUserPoolsTokenInvalid with
        // customAuthenticationInput.challengeParameters empty
        if ((self.currentUserState == .signedIn || self.currentUserState == .signedOutUserPoolsTokenInvalid) &&
            customAuthenticationInput.challengeParameters.isEmpty) {
            let username = self.userPoolClient?.currentUser()?.username ?? ""
            self.mobileClientStatusChanged(userState: .signedOutUserPoolsTokenInvalid,
                                           additionalInfo: ["username": username])
        } else {
            // If user is not signedIn, we reach here as part of the signIn flow. Next step
            // is to inform the user to enter custom auth challenge.
            let result = SignInResult(signInState: .customChallenge,
                                      parameters: customAuthenticationInput.challengeParameters,
                                      codeDetails: nil)
            invokeSignInCallback(signResult: result, error: nil)
        }
    }
    
    func didCompleteCustomAuthenticationStepWithError(_ error: Error?) {
        if let error = error {
            invokeSignInCallback(signResult: nil, error: AWSMobileClientError.makeMobileClientError(from: error))
        }
    }

    func getCode(_ authenticationInput: AWSCognitoIdentityMultifactorAuthenticationInput,
                 mfaCodeCompletionSource: AWSTaskCompletionSource<AWSCognitoIdentityMfaCodeDetails>) {
        self.userpoolOpsHelper.mfaCodeCompletionSource = mfaCodeCompletionSource
        var codeDeliveryDetails: UserCodeDeliveryDetails? = nil
            switch(authenticationInput.deliveryMedium) {
            case .email:
                codeDeliveryDetails = UserCodeDeliveryDetails(deliveryMedium: .email, destination: authenticationInput.destination, attributeName: "email")
            case .sms:
                codeDeliveryDetails = UserCodeDeliveryDetails(deliveryMedium: .sms, destination: authenticationInput.destination, attributeName: "phone")
            case .unknown:
                codeDeliveryDetails = UserCodeDeliveryDetails(deliveryMedium: .unknown, destination: authenticationInput.destination, attributeName: "unknown")
            @unknown default:
                codeDeliveryDetails = UserCodeDeliveryDetails(deliveryMedium: .unknown, destination: authenticationInput.destination, attributeName: "unknown")
        }
        
        let result = SignInResult(signInState: .smsMFA, codeDetails: codeDeliveryDetails)
        invokeSignInCallback(signResult: result, error: nil)
    }
    
    func didCompleteMultifactorAuthenticationStepWithError(_ error: Error?) {
        if let error = error {
            invokeSignInCallback(signResult: nil, error: AWSMobileClientError.makeMobileClientError(from: error))
        }
    }
}

//MARK: Extension to hold the keychain methods
extension AWSMobileClient {
    
    internal func setLoginProviderMetadataAndSaveInKeychain(provider: FederationProvider) {
        self.federationProvider = provider
        self.keychain.setString(provider.rawValue, forKey: FederationProviderKey)
        if let customRoleArn = self.customRoleArnInternal {
            self.keychain.setString(customRoleArn, forKey: CustomRoleArnKey)
        } else {
            self.keychain.removeItem(forKey: CustomRoleArnKey)
        }
        if federationDisabled {
            self.keychain.setString("true", forKey: FederationDisabledKey)
        }
    }
    
    internal func saveOAuthURIQueryParametersInKeychain() {
        self.keychain.setData(JSONHelper.dataFromDictionary(self.signInURIQueryParameters), forKey: SignInURIQueryParametersKey)
        self.keychain.setData(JSONHelper.dataFromDictionary(self.tokenURIQueryParameters), forKey: TokenURIQueryParametersKey)
        self.keychain.setData(JSONHelper.dataFromDictionary(self.signOutURIQueryParameters), forKey: SignOutURIQueryParametersKey)
    }
    
    internal func loadOAuthURIQueryParametersFromKeychain() {
        self.signInURIQueryParameters = JSONHelper.dictionaryFromData(self.keychain.data(forKey: SignInURIQueryParametersKey))
        self.tokenURIQueryParameters = JSONHelper.dictionaryFromData(self.keychain.data(forKey: TokenURIQueryParametersKey))
        self.signOutURIQueryParameters = JSONHelper.dictionaryFromData(self.keychain.data(forKey: SignOutURIQueryParametersKey))
    }
    
    internal func loadHostedUIScopesFromKeychain() {
        self.scopes = JSONHelper.arrayFromData(self.keychain.data(forKey: HostedUIOptionsScopesKey))
    }
    
    internal func saveHostedUIOptionsScopesInKeychain() {
        self.keychain.setData(JSONHelper.dataFromArray(self.scopes), forKey: HostedUIOptionsScopesKey)
    }
    
    internal func clearHostedUIOptionsScopesFromKeychain() {
        self.keychain.removeItem(forKey: HostedUIOptionsScopesKey)
    }
    
    internal func saveLoginsMapInKeychain() {
        if self.cachedLoginsMap.count == 0 {
            self.keychain.removeItem(forKey: LoginsMapKey)
            self.keychain.removeItem(forKey: FederationDisabledKey)
        } else {
            do {
                let data = try Data.init(base64Encoded: JSONEncoder().encode(self.cachedLoginsMap).base64EncodedData())
                self.keychain.setData(data, forKey: LoginsMapKey)
            } catch {
                print("could not save login map in cache")
            }
        }
    }
    
    internal func loadLoginsMapFromKeychain() {
        let data = self.keychain.data(forKey: LoginsMapKey)
        if data != nil {
            do {
                let dict = try JSONDecoder().decode([String: String].self, from: data!)
                self.cachedLoginsMap = dict
            } catch {
                print("Could not load login map from cache")
            }
        } else {
            self.cachedLoginsMap = [:]
        }
    }
    
    internal func loadFederationProviderMetadataFromKeychain() {
        if let federationProviderString = self.keychain.string(forKey: FederationProviderKey),
            let federationProvider = FederationProvider(rawValue: federationProviderString) {
            self.federationProvider = federationProvider
        }
        if let customRoleArnString = self.keychain.string(forKey: CustomRoleArnKey) {
            self.customRoleArnInternal = customRoleArnString
        }
        if let _ = self.keychain.string(forKey: FederationDisabledKey) {
            self.federationDisabled = true
        }
    }
}

extension AWSMobileClient: AWSCognitoAuthDelegate {
    
    public func getViewController() -> UIViewController {
        
        if let visibleViewController = developerNavigationController?.visibleViewController {
            return visibleViewController
        }
        
        if let rootViewController = UIApplication.shared.keyWindow?.rootViewController {
            return rootViewController
        } else if #available(iOS 13.0, *) {
            if #available(iOS 15.0, *) {
                return UIApplication.shared.connectedScenes
                    .compactMap { $0 as? UIWindowScene }
                    .filter { $0.activationState == .foregroundActive }
                    .first?.keyWindow?.rootViewController ?? UIViewController()
            } else {
                return UIApplication.shared.connectedScenes
                    .compactMap { $0 as? UIWindowScene }
                    .filter { $0.activationState == .foregroundActive }
                    .first?.windows
                    .first(where: \.isKeyWindow)?.rootViewController ?? UIViewController()
            }
        }
        
        // un-expected return an redandunt instance of UIViewController
        return UIViewController()
    }
    
    public func shouldLaunchSignInVCIfRefreshTokenIsExpired() -> Bool {
        return false
    }
}
