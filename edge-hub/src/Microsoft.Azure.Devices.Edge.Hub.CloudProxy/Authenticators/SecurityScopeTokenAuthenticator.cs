// Copyright (c) Microsoft. All rights reserved.
namespace Microsoft.Azure.Devices.Edge.Hub.Core
{
    using System;
    using System.Threading.Tasks;
    using Microsoft.Azure.Devices.Common.Data;
    using Microsoft.Azure.Devices.Common.Security;
    using Microsoft.Azure.Devices.Edge.Hub.Core.Cloud;
    using Microsoft.Azure.Devices.Edge.Hub.Core.Device;
    using Microsoft.Azure.Devices.Edge.Hub.Core.Identity;
    using Microsoft.Azure.Devices.Edge.Util;

    public class SecurityScopeTokenAuthenticator : IAuthenticator
    {
        readonly ISecurityScopeEntitiesCache securityScopeEntitiesCache;
        readonly string iothubHostName;
        readonly string edgeHubHostName;
        readonly IAuthenticator underlyingAuthenticator;
        readonly IConnectionManager connectionManager;

        public SecurityScopeTokenAuthenticator(ISecurityScopeEntitiesCache securityScopeEntitiesCache,
            string iothubHostName,
            string edgeHubHostName,
            IAuthenticator underlyingAuthenticator,
            IConnectionManager connectionManager)
        {
            this.underlyingAuthenticator = Preconditions.CheckNotNull(underlyingAuthenticator, nameof(underlyingAuthenticator));
            this.securityScopeEntitiesCache = Preconditions.CheckNotNull(securityScopeEntitiesCache, nameof(securityScopeEntitiesCache));
            this.iothubHostName = Preconditions.CheckNonWhiteSpace(iothubHostName, nameof(iothubHostName));
            this.edgeHubHostName = Preconditions.CheckNonWhiteSpace(edgeHubHostName, nameof(edgeHubHostName));
            this.connectionManager = Preconditions.CheckNotNull(connectionManager, nameof(connectionManager));
            this.securityScopeEntitiesCache.ServiceIdentityUpdated += this.HandleServiceIdentityUpdate;
            this.securityScopeEntitiesCache.ServiceIdentityRemoved += this.HandleServiceIdentityRemove;
        }

        async void HandleServiceIdentityUpdate(object sender, ServiceIdentity serviceIdentity)
        {
            try
            {
                Option<IClientCredentials> clientCredentials = this.connectionManager.GetClientCredentials(serviceIdentity.Id);
                await clientCredentials.ForEachAsync(
                    async c =>
                    {
                        if (!(await this.AuthenticateInternalAsync(c)))
                        {
                            await this.connectionManager.RemoveDeviceConnection(c.Identity.Id);
                        }
                    });
            }
            catch (Exception)
            {
                // Log
            }
        }

        async void HandleServiceIdentityRemove(object sender, string id)
        {
            try
            {
                await this.connectionManager.RemoveDeviceConnection(id);
            }
            catch (Exception)
            {
                // Log
            }
        }

        public async Task<bool> AuthenticateAsync(IClientCredentials clientCredentials)
        {
            if (!(clientCredentials is ITokenCredentials tokenCredentials))
            {
                return false;
            }

            bool result = await this.AuthenticateInternalAsync(clientCredentials)
                || await this.underlyingAuthenticator.AuthenticateAsync(clientCredentials);
            return result;
        }

        async Task<bool> AuthenticateInternalAsync(IClientCredentials clientCredentials)
        {
            if (!(clientCredentials is ITokenCredentials tokenCredentials))
            {
                return false;
            }

            SharedAccessSignature sharedAccessSignature = SharedAccessSignature.Parse(this.iothubHostName, tokenCredentials.Token);
            bool result = await this.ValidateToken(sharedAccessSignature, tokenCredentials.Identity.Id);
            if (!result && tokenCredentials.Identity is IModuleIdentity moduleIdentity)
            {
                result = await this.ValidateToken(sharedAccessSignature, moduleIdentity.DeviceId);
            }
            return result;
        }

        async Task<bool> ValidateToken(SharedAccessSignature sharedAccessSignature, string id)
        {
            Option<ServiceIdentity> serviceIdentity = await this.securityScopeEntitiesCache.GetServiceIdentity(id);

            return serviceIdentity.Map(
                    s =>
                    {
                        // Validate token
                        Try<bool> result = this.ValidateTokenWithSecurityIdentity(sharedAccessSignature, s);
                        return result.Success;
                    })
                .GetOrElse(
                    () =>
                    {
                        // Log
                        return false;
                    });
        }

        Try<bool> ValidateTokenWithSecurityIdentity(SharedAccessSignature sharedAccessSignature, ServiceIdentity serviceIdentity)
        {
            var rule = new SharedAccessSignatureAuthorizationRule
            {
                PrimaryKey = serviceIdentity.Authentication.SymmetricKey.PrimaryKey,
                SecondaryKey = serviceIdentity.Authentication.SymmetricKey.SecondaryKey
            };
            try
            {
                sharedAccessSignature.Authenticate(rule);
                return Try.Success(true);
            }
            catch (UnauthorizedAccessException e)
            {
                return Try<bool>.Failure(e);
            }
        }
    }
}
