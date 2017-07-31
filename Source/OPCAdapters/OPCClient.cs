//******************************************************************************************************
//  OPCClient.cs - Gbtc
//
//  Copyright © 2017, Grid Protection Alliance.  All Rights Reserved.
//
//  Licensed to the Grid Protection Alliance (GPA) under one or more contributor license agreements. See
//  the NOTICE file distributed with this work for additional information regarding copyright ownership.
//  The GPA licenses this file to you under the GNU General Public License 2.0, the "License"; you may
//  not use this file except in compliance with the License. You may obtain a copy of the License at:
//
//      https://opensource.org/licenses/GPL-2.0
//
//  Unless agreed to in writing, the subject software distributed under the License is distributed on an
//  "AS-IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. Refer to the
//  License for the specific language governing permissions and limitations.
//
//  Code Modification History:
//  ----------------------------------------------------------------------------------------------------
//  07/27/2017 - J. Ritchie Carroll
//       Generated original version of source code.
//
//******************************************************************************************************

using System;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using GSF.Diagnostics;
using GSF.TimeSeries.Adapters;
using Opc.Ua;
using Opc.Ua.Client;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Security.Cryptography;

namespace OPCAdapters
{
    /// <summary>
    /// Defines an input adapter for a time-series library application that
    /// acts as an OPC client to an OPC server.
    /// </summary>
    public class OPCClient : InputAdapterBase
    {
        #region [ Members ]

        // Nested Types

        // Constants

        // Delegates

        // Events

        // Fields
        private ConfiguredEndpoint m_defaultEndpoint;
        private ApplicationConfiguration m_configuration;
        private ServiceMessageContext m_messageContext;
        private BindingFactory m_bindingFactory;
        private Session m_session;
        private bool m_stopped;

        #endregion

        #region [ Constructors ]

        #endregion

        #region [ Properties ]

        public override bool SupportsTemporalProcessing => false;

        protected override bool UseAsyncConnect => false;

        #endregion

        #region [ Methods ]

        public override void Initialize()
        {
            base.Initialize();

            //SecurityConfiguration securityConfig = new SecurityConfiguration();
            //securityConfig.ConfigureFirewall = false;

            //ApplicationConfiguration appConfig = new ApplicationConfiguration();

            //appConfig.ApplicationName = $"OPCClient: {Name}";
            //appConfig.ApplicationType = ApplicationType.Client;
            //appConfig.ProductUri = "https://github.com/GridProtectionAlliance/gsf";
            //appConfig.SecurityConfiguration = securityConfig;

            //string url = "load from configuration";
            //EndpointDescription endpointDescription = new EndpointDescription(url);
            //endpointDescription.

            //EndpointConfiguration endpointConfig = new EndpointConfiguration();
            //endpointConfig.UseBinaryEncoding = true;

            //SessionChannel channel = SessionChannel.Create(appConfig, endpointConfig, appConfig.ApplicationName);

            //m_session = new Session()

            // Initialize the client configuration.
            ApplicationConfiguration configuration = new ApplicationConfiguration();

            // Need to specify the application instance certificate for the client.
            configuration.SecurityConfiguration.ApplicationCertificate = new CertificateIdentifier();
            configuration.SecurityConfiguration.ApplicationCertificate.StoreType = Utils.DefaultStoreType;
            configuration.SecurityConfiguration.ApplicationCertificate.StorePath = Utils.DefaultStorePath;
            configuration.SecurityConfiguration.ApplicationCertificate.SubjectName = $"TSL OPC Client: {Name}";

            // set the session keep alive to 5 seconds.
            configuration.ClientConfiguration.DefaultSessionTimeout = 500000;

            m_configuration = configuration;
            m_messageContext = configuration.CreateMessageContext();
            m_stopped = false;
            
            //m_performanceData = new List<PerfData>();
        }

        public override string GetShortStatus(int maxLength)
        {
            throw new NotImplementedException();
        }

        protected override void AttemptConnection()
        {
            throw new NotImplementedException();
        }

        protected override void AttemptDisconnection()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates a session.
        /// </summary>
        private Session CreateSession(ApplicationConfiguration configuration, BindingFactory bindingFactory, ConfiguredEndpoint endpoint, IUserIdentity identity)
        {
            Report("Creating new Session with URL = {0}", endpoint.EndpointUrl);

            // Initialize the channel which will be created with the server.
            ITransportChannel channel = SessionChannel.Create(
                configuration,
                endpoint.Description,
                endpoint.Configuration,
                configuration.SecurityConfiguration.ApplicationCertificate.Find(true),
                configuration.CreateMessageContext());

            // Wrap the channel with the session object.
            Session session = new Session(channel, configuration, endpoint, null);
            session.ReturnDiagnostics = DiagnosticsMasks.All;

            // register keep alive callback.
            session.KeepAlive += new KeepAliveEventHandler(Session_KeepAlive);

            // create the user identity.            
            if (identity == null)
            {
                if (endpoint.Description.UserIdentityTokens.Count > 0)
                    identity = CreateUserIdentity(endpoint.Description.UserIdentityTokens[0]);
            }

            // Create the session. This actually connects to the server.
            session.Open(Guid.NewGuid().ToString(), identity);

            Report("Successfully created new Session.");

            // return the session.
            return session;
        }

        /// <summary>
        /// Creates a user identity for the policy.
        /// </summary>
        private IUserIdentity CreateUserIdentity(UserTokenPolicy policy)
        {
            if (policy == null || policy.TokenType == UserTokenType.Anonymous)
                return null;

            if (policy.TokenType == UserTokenType.UserName)
                return new UserIdentity("SomeUser", "password");

            if (policy.TokenType == UserTokenType.Certificate)
            {
                X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

                try
                {
                    foreach (X509Certificate2 certificate in store.Certificates)
                    {
                        if (certificate.HasPrivateKey)
                            return new UserIdentity(certificate);
                    }

                    return null;
                }
                finally
                {
                    store.Close();
                }
            }

            if (policy.TokenType == UserTokenType.IssuedToken)
            {
                CertificateIdentifier userid = new CertificateIdentifier();

                userid.StoreType = CertificateStoreType.Windows;
                userid.StorePath = "LocalMachine\\Root";
                userid.SubjectName = "UASampleRoot";

                X509Certificate2 certificate = userid.Find();
                X509SecurityToken signingToken = new X509SecurityToken(certificate);

                SamlSecurityToken token = CreateSAMLToken("someone@somewhere.com", signingToken);

                return new UserIdentity(token);
            }

            throw ServiceResultException.Create(StatusCodes.BadSecurityPolicyRejected, "User token policy is not supported.");
        }

        /// <summary>
        /// Creates a SAML token for the specified email address and security token.
        /// </summary>
        private SamlSecurityToken CreateSAMLToken(string emailAddress, X509SecurityToken issuerToken)
        {
            // Create list of confirmation strings
            List<string> confirmations = new List<string>();

            // Add holder-of-key string to list of confirmation strings
            confirmations.Add("urn:oasis:names:tc:SAML:1.0:cm:bearer");

            // Create SAML subject statement based on issuer member variable, confirmation string collection 
            // local variable and proof key identifier parameter
            SamlSubject subject = new SamlSubject("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", null, emailAddress);

            // Create a list of SAML attributes
            List<SamlAttribute> attributes = new List<SamlAttribute>();
            Claim claim = Claim.CreateNameClaim(emailAddress);
            attributes.Add(new SamlAttribute(claim));

            // Create list of SAML statements
            List<SamlStatement> statements = new List<SamlStatement>();

            // Add a SAML attribute statement to the list of statements. Attribute statement is based on 
            // subject statement and SAML attributes resulting from claims
            statements.Add(new SamlAttributeStatement(subject, attributes));

            // Create a valid from/until condition
            DateTime validFrom = DateTime.UtcNow;
            DateTime validTo = DateTime.UtcNow.AddHours(12);

            SamlConditions conditions = new SamlConditions(validFrom, validTo);

            // Create the SAML assertion
            SamlAssertion assertion = new SamlAssertion(
                "_" + Guid.NewGuid().ToString(),
                issuerToken.Certificate.Subject,
                validFrom,
                conditions,
                null,
                statements);

            SecurityKey signingKey = new RsaSecurityKey((RSA)issuerToken.Certificate.PrivateKey);

            // Set the signing credentials for the SAML assertion
            assertion.SigningCredentials = new SigningCredentials(
                signingKey,
                System.IdentityModel.Tokens.SecurityAlgorithms.RsaSha1Signature,
                System.IdentityModel.Tokens.SecurityAlgorithms.Sha1Digest,
                new SecurityKeyIdentifier(issuerToken.CreateKeyIdentifierClause<X509ThumbprintKeyIdentifierClause>()));

            return new SamlSecurityToken(assertion);
        }

        /// <summary>
        /// Returns the a session to re-use for different tests.
        /// </summary>
        private Session GetDefaultSession()
        {
            if (m_session == null)
            {
                DateTime start = DateTime.UtcNow;
                m_session = CreateSession(m_configuration, m_bindingFactory, m_defaultEndpoint, null);

                if ((DateTime.UtcNow - start).TotalSeconds > 10)
                    Report("WARNING: Unexpected delay creating a Session, could be due to WCF DNS lookup problem. Delay={0}s", (DateTime.UtcNow - start).TotalSeconds);

                // fetch the reference type tree.
                m_session.FetchTypeTree(ReferenceTypeIds.References);
                Report("Fetched the known ReferenceTypes from the Server");

                // fetch the data type tree.
                m_session.FetchTypeTree(DataTypeIds.BaseDataType);
                Report("Fetched the known DataTypes from the Server");
            }

            return m_session;
        }

        /// <summary>
        /// Raised when a keep alive response is returned from the server.
        /// </summary>
        private void Session_KeepAlive(Session session, KeepAliveEventArgs e)
        {
            if (ServiceResult.IsBad(e.Status))
                Report("KEEP ALIVE LATE: {0}", e.Status);
        }

        private void Report(string format, params object[] args) => OnStatusMessage(MessageLevel.Info, string.Format(format, args));

        #endregion
    }
}
