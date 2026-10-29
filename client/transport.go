package client


import (
	"context"
	"net/http"

	openapiTypes "github.com/oapi-codegen/runtime/types"

	"github.com/anywaye/identity/client/generated"
)

// Transport is the generated transport's shape, restated as this package's own
// interface.
//
// One method per `operationId`. The names are the contract: `operationId` is what
// every generated client in the fleet names its method after, so a Go client that
// called this `GetMe` where `anywaye-ts` says `getCurrentUser` would be a divergence
// in three clients for one platform — which the fleet treats as a defect in the
// platform, not a style difference.
type Transport interface {
	CreateSession(ctx context.Context, body generated.CreateSessionJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RegisterUser(ctx context.Context, body generated.RegisterUserJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DeleteSession(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListSessions(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DeleteSessionByID(ctx context.Context, sessionId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	CompleteSecondFactor(ctx context.Context, body generated.CompleteSecondFactorJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	MintSessionToken(ctx context.Context, body generated.MintSessionTokenJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetMFAStatus(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DisableMFA(ctx context.Context, body generated.DisableMFAJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	StartMFAEnrollment(ctx context.Context, body generated.StartMFAEnrollmentJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmMFAEnrollment(ctx context.Context, enrollmentId openapiTypes.UUID, body generated.ConfirmMFAEnrollmentJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RegenerateMFARecoveryCodes(ctx context.Context, body generated.RegenerateMFARecoveryCodesJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetCurrentUser(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	UpdateCurrentUser(ctx context.Context, body generated.UpdateCurrentUserJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DeleteCurrentUser(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RequestPasswordReset(ctx context.Context, body generated.RequestPasswordResetJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmPasswordReset(ctx context.Context, body generated.ConfirmPasswordResetJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RequestEmailVerification(ctx context.Context, body generated.RequestEmailVerificationJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmEmailVerification(ctx context.Context, body generated.ConfirmEmailVerificationJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetEmailVerificationStatus(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RequestEmailChange(ctx context.Context, body generated.RequestEmailChangeJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmEmailChangeCurrentAddress(ctx context.Context, body generated.ConfirmEmailChangeCurrentAddressJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ConfirmEmailChangeNewAddress(ctx context.Context, body generated.ConfirmEmailChangeNewAddressJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	CreateAccount(ctx context.Context, body generated.CreateAccountJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListAccounts(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetAccount(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RenameAccount(ctx context.Context, accountId openapiTypes.UUID, body generated.RenameAccountJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DeleteAccount(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListMembers(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	InviteMember(ctx context.Context, accountId openapiTypes.UUID, body generated.InviteMemberJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ChangeMemberRole(ctx context.Context, accountId openapiTypes.UUID, userId openapiTypes.UUID, body generated.ChangeMemberRoleJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RemoveMember(ctx context.Context, accountId openapiTypes.UUID, userId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	TransferAccountOwnership(ctx context.Context, accountId openapiTypes.UUID, body generated.TransferAccountOwnershipJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	AcceptInvitation(ctx context.Context, body generated.AcceptInvitationJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ClaimAgent(ctx context.Context, accountId openapiTypes.UUID, body generated.ClaimAgentJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RegisterOIDCClient(ctx context.Context, accountId openapiTypes.UUID, body generated.RegisterOIDCClientJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListOIDCClients(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetOIDCClient(ctx context.Context, accountId openapiTypes.UUID, clientId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeOIDCClient(ctx context.Context, accountId openapiTypes.UUID, clientId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	MintAPIKey(ctx context.Context, accountId openapiTypes.UUID, body generated.MintAPIKeyJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListAPIKeys(ctx context.Context, accountId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeAPIKey(ctx context.Context, accountId openapiTypes.UUID, keyId openapiTypes.UUID, body generated.RevokeAPIKeyJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	IntrospectAPIKey(ctx context.Context, body generated.IntrospectAPIKeyJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	MintSessionLink(ctx context.Context, body generated.MintSessionLinkJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RedeemSessionLink(ctx context.Context, body generated.RedeemSessionLinkJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	Liveness(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	Readiness(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	MintSignupTimestamp(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListAccountAuditLog(ctx context.Context, accountId openapiTypes.UUID, params *generated.ListAccountAuditLogParams, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	DisableUser(ctx context.Context, userId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	EnableUser(ctx context.Context, userId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetOperatorMe(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	SearchOperatorUsers(ctx context.Context, params *generated.SearchOperatorUsersParams, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetOperatorSummary(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	SearchOperatorAccounts(ctx context.Context, params *generated.SearchOperatorAccountsParams, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	StaffDisableUser(ctx context.Context, userId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	StaffEnableUser(ctx context.Context, userId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeAccountInvitation(ctx context.Context, accountId openapiTypes.UUID, invitationId openapiTypes.UUID, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeAccountInvitations(ctx context.Context, accountId openapiTypes.UUID, body generated.BulkInvitationRevocation, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	StartSocialLogin(ctx context.Context, provider generated.StartSocialLoginParamsProvider, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	CompleteSocialLogin(ctx context.Context, provider generated.CompleteSocialLoginParamsProvider, params *generated.CompleteSocialLoginParams, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RegisterAgent(ctx context.Context, body generated.RegisterAgentJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetAgentClaimPreview(ctx context.Context, token string, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	GetAgentHome(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RefreshAgentClaimLink(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	MintAgentToken(ctx context.Context, body generated.MintAgentTokenJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	ListAgentTokens(ctx context.Context, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RevokeAgentToken(ctx context.Context, tokenID openapiTypes.UUID, body generated.RevokeAgentTokenJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
	RotateAgentToken(ctx context.Context, tokenID openapiTypes.UUID, body generated.RotateAgentTokenJSONRequestBody, reqEditors ...generated.RequestEditorFn) (*http.Response, error)
}

var _ Transport = (*generated.Client)(nil)

func newTransport(baseURL, token string) (Transport, error) {
	httpClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	options := []generated.ClientOption{generated.WithHTTPClient(httpClient)}
	if token != "" {
		options = append(options, generated.WithRequestEditorFn(
			func(ctx context.Context, req *http.Request) error {
				return AttachCredential(req, token)
			}))
	}

	return generated.NewClient(baseURL, options...)
}
