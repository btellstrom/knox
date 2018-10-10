/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.knox.gateway.dispatch;

import java.io.IOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.Principal;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.servlet.FilterConfig;

import org.apache.hc.client5.http.HttpRequestRetryHandler;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.auth.AuthSchemeProvider;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.KerberosConfig;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.config.AuthSchemes;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.impl.DefaultConnectionKeepAliveStrategy;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.ManagedHttpClientConnection;
import org.apache.hc.client5.http.protocol.RedirectStrategy;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.ProtocolException;
import org.apache.hc.core5.http.config.H1Config;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.impl.DefaultConnectionReuseStrategy;
import org.apache.hc.core5.http.io.HttpConnectionFactory;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.knox.gateway.services.security.AliasService;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.KeystoreService;
import org.apache.knox.gateway.services.security.MasterService;
import org.apache.knox.gateway.config.GatewayConfig;
import org.apache.knox.gateway.services.GatewayServices;
import org.apache.knox.gateway.services.metrics.MetricsService;
import org.joda.time.Period;
import org.joda.time.format.PeriodFormatter;
import org.joda.time.format.PeriodFormatterBuilder;

public class DefaultHttpClientFactory implements HttpClientFactory {

  @Override
  public HttpClient createHttpClient(FilterConfig filterConfig) {
    HttpClientBuilder builder = null;
    GatewayConfig gatewayConfig = (GatewayConfig) filterConfig.getServletContext().getAttribute(GatewayConfig.GATEWAY_CONFIG_ATTRIBUTE);
    GatewayServices services = (GatewayServices) filterConfig.getServletContext()
        .getAttribute(GatewayServices.GATEWAY_SERVICES_ATTRIBUTE);
    if (gatewayConfig != null && gatewayConfig.isMetricsEnabled()) {
      MetricsService metricsService = services.getService(GatewayServices.METRICS_SERVICE);
      builder = metricsService.getInstrumented(HttpClientBuilder.class);
    } else {
      builder = HttpClients.custom();
    }

    PoolingHttpClientConnectionManagerBuilder cmBuilder = PoolingHttpClientConnectionManagerBuilder.create();

    if (Boolean.parseBoolean(filterConfig.getInitParameter("useTwoWaySsl"))) {
      char[] keypass = null;
      MasterService ms = services.getService("MasterService");
      AliasService as = services.getService(GatewayServices.ALIAS_SERVICE);
      try {
        keypass = as.getGatewayIdentityPassphrase();
      } catch (AliasServiceException e) {
        // nop - default passphrase will be used
      }
      if (keypass == null) {
        // there has been no alias created for the key - let's assume it is the same as the keystore password
        keypass = ms.getMasterSecret();
      }

      KeystoreService ks = services.getService(GatewayServices.KEYSTORE_SERVICE);
      final SSLContext sslcontext;
      try {
        KeyStore keystoreForGateway = ks.getKeystoreForGateway();
        sslcontext = SSLContexts.custom()
            .loadTrustMaterial(keystoreForGateway, new TrustSelfSignedStrategy())
            .loadKeyMaterial(keystoreForGateway, keypass)
            .build();
      } catch (Exception e) {
        throw new IllegalArgumentException("Unable to create SSLContext", e);
      }
      SSLConnectionSocketFactory sslConnectionSocketFactory = new SSLConnectionSocketFactory(sslcontext);
      cmBuilder.setSSLSocketFactory(sslConnectionSocketFactory);
    }
    if ( "true".equals(System.getProperty(GatewayConfig.HADOOP_KERBEROS_SECURED)) ) {
      BasicCredentialsProvider credentialsProvider = new BasicCredentialsProvider();
      credentialsProvider.setCredentials(
          new AuthScope(null, null, -1, null, null),
          new UseJaasCredentials());

      Registry<AuthSchemeProvider> authSchemeRegistry = RegistryBuilder.<AuthSchemeProvider>create()
          .register(AuthSchemes.SPNEGO, new KnoxSpnegoAuthSchemeFactory(KerberosConfig.DEFAULT, SystemDefaultDnsResolver.INSTANCE))
          .build();

      builder.setDefaultAuthSchemeRegistry(authSchemeRegistry)
          .setDefaultCookieStore(new HadoopAuthCookieStore(gatewayConfig))
          .setDefaultCredentialsProvider(credentialsProvider);
    } else {
      builder.setDefaultCookieStore(new NoCookieStore());
    }

    builder.setKeepAliveStrategy( DefaultConnectionKeepAliveStrategy.INSTANCE );
    builder.setConnectionReuseStrategy( DefaultConnectionReuseStrategy.INSTANCE );
    builder.setRedirectStrategy( new NeverRedirectStrategy() );
    builder.setRetryHandler( new NeverRetryHandler() );

    RequestConfig requestConfig = getRequestConfig(filterConfig);
    builder.setDefaultRequestConfig( requestConfig  );

    int maxConnections = getMaxConnections( filterConfig );
    cmBuilder
        .setMaxConnPerRoute(maxConnections)
        .setMaxConnTotal(maxConnections);

    final H1Config h1Config = H1Config.custom()
                                  .setChunkSizeHint(Integer.parseInt(System.getProperty("KNOX_CHUNKSIZE", "2028")))
                                  .build();
    final HttpConnectionFactory<ManagedHttpClientConnection> connFactory =
        new ManagedHttpClientConnectionFactory(h1Config, null, null);
    cmBuilder.setConnectionFactory(connFactory);
    
    builder.setConnectionManager(cmBuilder.build());

    // See KNOX-1530 for details
    builder.disableContentCompression();

    return builder.build();
  }

  private static RequestConfig getRequestConfig(FilterConfig config ) {
    RequestConfig.Builder builder = RequestConfig.custom();
    int connectionTimeout = getConnectionTimeout( config );
    if ( connectionTimeout != -1 ) {
      builder.setConnectTimeout( connectionTimeout, TimeUnit.MILLISECONDS );
      builder.setConnectionRequestTimeout( connectionTimeout, TimeUnit.MILLISECONDS );
    }
//    int socketTimeout = getSocketTimeout( config );
//    if( socketTimeout != -1 ) {
//      builder.setSocketTimeout( socketTimeout );
//    }
    return builder.build();
  }

  private static class NoCookieStore implements CookieStore {
    @Override
    public void addCookie(Cookie cookie) {
      //no op
    }

    @Override
    public List<Cookie> getCookies() {
      return Collections.emptyList();
    }

    @Override
    public boolean clearExpired(Date date) {
      return true;
    }

    @Override
    public void clear() {
      //no op
    }
  }

  private static class NeverRedirectStrategy implements RedirectStrategy {
    @Override
    public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context )
        throws ProtocolException {
      return false;
    }

    @Override
    public URI getLocationURI(HttpRequest request, HttpResponse response, HttpContext context) throws HttpException {
      return null;
    }
  }

  private static class NeverRetryHandler implements HttpRequestRetryHandler {
    @Override
    public boolean retryRequest(HttpRequest request, IOException exception, int executionCount, HttpContext context) {
      return false;
    }
  }

  private static class UseJaasCredentials implements Credentials {

    @Override
    public char[] getPassword() {
      return null;
    }

    @Override
    public Principal getUserPrincipal() {
      return null;
    }

  }

  private int getMaxConnections( FilterConfig filterConfig ) {
    int maxConnections = 32;
    GatewayConfig config =
        (GatewayConfig)filterConfig.getServletContext().getAttribute( GatewayConfig.GATEWAY_CONFIG_ATTRIBUTE );
    if( config != null ) {
      maxConnections = config.getHttpClientMaxConnections();
    }
    String str = filterConfig.getInitParameter( "httpclient.maxConnections" );
    if( str != null ) {
      try {
        maxConnections = Integer.parseInt( str );
      } catch ( NumberFormatException e ) {
        // Ignore it and use the default.
      }
    }
    return maxConnections;
  }

  private static int getConnectionTimeout( FilterConfig filterConfig ) {
    int timeout = -1;
    GatewayConfig globalConfig =
        (GatewayConfig)filterConfig.getServletContext().getAttribute( GatewayConfig.GATEWAY_CONFIG_ATTRIBUTE );
    if( globalConfig != null ) {
      timeout = globalConfig.getHttpClientConnectionTimeout();
    }
    String str = filterConfig.getInitParameter( "httpclient.connectionTimeout" );
    if( str != null ) {
      try {
        timeout = (int)parseTimeout( str );
      } catch ( Exception e ) {
        // Ignore it and use the default.
      }
    }
    return timeout;
  }

  private static int getSocketTimeout( FilterConfig filterConfig ) {
    int timeout = -1;
    GatewayConfig globalConfig =
        (GatewayConfig)filterConfig.getServletContext().getAttribute( GatewayConfig.GATEWAY_CONFIG_ATTRIBUTE );
    if( globalConfig != null ) {
      timeout = globalConfig.getHttpClientSocketTimeout();
    }
    String str = filterConfig.getInitParameter( "httpclient.socketTimeout" );
    if( str != null ) {
      try {
        timeout = (int)parseTimeout( str );
      } catch ( Exception e ) {
        // Ignore it and use the default.
      }
    }
    return timeout;
  }

  private static long parseTimeout( String s ) {
    PeriodFormatter f = new PeriodFormatterBuilder()
        .appendMinutes().appendSuffix("m"," min")
        .appendSeconds().appendSuffix("s"," sec")
        .appendMillis().toFormatter();
    Period p = Period.parse( s, f );
    return p.toStandardDuration().getMillis();
  }

}
