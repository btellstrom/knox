/**
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
package org.apache.hadoop.gateway.deploy;

import org.apache.hadoop.gateway.GatewayMessages;
import org.apache.hadoop.gateway.GatewayResources;
import org.apache.hadoop.gateway.GatewayServlet;
import org.apache.hadoop.gateway.config.GatewayConfig;
import org.apache.hadoop.gateway.descriptor.GatewayDescriptor;
import org.apache.hadoop.gateway.descriptor.GatewayDescriptorFactory;
import org.apache.hadoop.gateway.i18n.messages.MessagesFactory;
import org.apache.hadoop.gateway.i18n.resources.ResourcesFactory;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Service;
import org.apache.hadoop.gateway.topology.Topology;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.Asset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.descriptor.api.Descriptors;
import org.jboss.shrinkwrap.descriptor.api.webapp30.WebAppDescriptor;
import org.jboss.shrinkwrap.descriptor.api.webcommon30.ServletType;

import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

public abstract class DeploymentFactory {

  private static GatewayResources res = ResourcesFactory.get( GatewayResources.class );
  private static GatewayMessages log = MessagesFactory.get( GatewayMessages.class );

  //private static Set<ServiceDeploymentContributor> SERVICE_CONTRIBUTORS;
  private static Map<String,Map<String,ServiceDeploymentContributor>> SERVICE_CONTRIBUTOR_MAP;
  static {
    loadServiceContributors();
  }

  private static Set<ProviderDeploymentContributor> PROVIDER_CONTRIBUTORS;
  private static Map<String,Map<String,ProviderDeploymentContributor>> PROVIDER_CONTRIBUTOR_MAP;
  static {
    loadProviderContributors();
  }

  public static WebArchive createDeployment( GatewayConfig config, Topology topology ) {
    Map<String,List<ProviderDeploymentContributor>> providers = selectContextProviders( topology );
    Map<String,List<ServiceDeploymentContributor>> services = selectContextServices( topology );
    DeploymentContext context = createDeploymentContext( config, topology, providers, services );
    initialize( context, providers, services );
    contribute( context, providers, services );
    finalize( context, providers, services );
    return context.getWebArchive();
  }

  private static DeploymentContext createDeploymentContext(
      GatewayConfig config, Topology topology,
      Map<String,List<ProviderDeploymentContributor>> providers,
      Map<String,List<ServiceDeploymentContributor>> services ) {
    WebArchive webArchive = ShrinkWrap.create( WebArchive.class, topology.getName() );
    WebAppDescriptor webAppDesc = Descriptors.create( WebAppDescriptor.class );
    GatewayDescriptor gateway = GatewayDescriptorFactory.create();
    DeploymentContext context = new DeploymentContextImpl(
        config, topology, gateway, webArchive, webAppDesc, providers, services );
    return context;
  }

  // Scan through the providers in the topology.  Collect any named providers in their roles list.
  // Scan through all of the loaded providers.  For each that doesn't have an existing provider in the role
  // list add it.
  private static Map<String,List<ProviderDeploymentContributor>> selectContextProviders( Topology topology ) {
    Map<String,List<ProviderDeploymentContributor>> providers
        = new HashMap<String,List<ProviderDeploymentContributor>>();
    collectTopologyProviders( topology, providers );
    collectDefaultProviders( providers );
    return providers;
  }

  private static void collectTopologyProviders(
      Topology topology, Map<String, List<ProviderDeploymentContributor>> defaults ) {
    for( Provider provider : topology.getProviders() ) {
      String name = provider.getName();
      if( name != null ) {
        String role = provider.getRole();
        Map<String,ProviderDeploymentContributor> nameMap = PROVIDER_CONTRIBUTOR_MAP.get( role );
        if( nameMap != null ) {
          ProviderDeploymentContributor contributor = nameMap.get( name );
          if( contributor != null ) {
            List list = defaults.get( role );
            if( list == null ) {
              list = new ArrayList( 1 );
              defaults.put( role, list );
            }
            if( !list.contains( contributor ) ) {
              list.add( contributor );
            }
          }
        }
      }
    }
  }

  private static void collectDefaultProviders( Map<String,List<ProviderDeploymentContributor>> defaults ) {
    for( ProviderDeploymentContributor contributor : PROVIDER_CONTRIBUTORS ) {
      String role = contributor.getRole();
      List<ProviderDeploymentContributor> list = defaults.get( role );
      if( list == null ) {
        list = new ArrayList<ProviderDeploymentContributor>();
        defaults.put( role, list );
      }
      if( list.isEmpty() ) {
        list.add( contributor );
      }
    }
  }

  // Scan through the services in the topology.
  // For each that we find add it to the list of service roles included in the topology.
  private static Map<String,List<ServiceDeploymentContributor>> selectContextServices( Topology topology ) {
    Map<String,List<ServiceDeploymentContributor>> defaults
        = new HashMap<String,List<ServiceDeploymentContributor>>();
    for( Service service : topology.getServices() ) {
      String role = service.getRole();
      ServiceDeploymentContributor contributor = getServiceContributor( role, service.getName() );
      if( contributor != null ) {
        List<ServiceDeploymentContributor> list = defaults.get( role );
        if( list == null ) {
          list = new ArrayList<ServiceDeploymentContributor>( 1 );
          defaults.put( role, list );
        }
        if( !list.contains( contributor ) ) {
          list.add( contributor );
        }
      }
    }
    return defaults;
  }

  private static void initialize(
      DeploymentContext context,
      Map<String,List<ProviderDeploymentContributor>> providers,
      Map<String,List<ServiceDeploymentContributor>> services ) {
    WebAppDescriptor wad = context.getWebAppDescriptor();
    String servlet = context.getTopology().getName();
    wad.createServlet().servletName( servlet ).servletClass( GatewayServlet.class.getName() );
    wad.createServletMapping().servletName( servlet ).urlPattern( "/*" );
    for( String role : providers.keySet() ) {
      for( ProviderDeploymentContributor contributor : providers.get( role ) ) {
        try {
          contributor.initializeContribution( context );
        } catch( Exception e ) {
          //TODO: I18N message.
          e.printStackTrace();
        }
      }
    }
    for( String role : services.keySet() ) {
      for( ServiceDeploymentContributor contributor : services.get( role ) ) {
        try {
          contributor.initializeContribution( context );
        } catch( Exception e ) {
          //TODO: I18N message.
          e.printStackTrace();
        }
      }
    }
  }
  
  private static void contribute(
      DeploymentContext context,
      Map<String,List<ProviderDeploymentContributor>> providers,
      Map<String,List<ServiceDeploymentContributor>> services ) {
      Topology topology = context.getTopology();
    for( Provider provider : topology.getProviders() ) {
      ProviderDeploymentContributor contributor = getProviderContributor( providers, provider.getRole(), provider.getName() );
      if( contributor != null && provider.isEnabled() ) {
        try {
          contributor.contributeProvider( context, provider );
        } catch( Exception e ) {
          //TODO: I18N message.
          e.printStackTrace();
        }
      }
    }
    for( Service service : topology.getServices() ) {
      ServiceDeploymentContributor contributor = getServiceContributor( service.getRole(), null );
      if( contributor != null ) {
        try {
          contributor.contributeService( context, service );
        } catch( Exception e ) {
          //TODO: I18N message.
          e.printStackTrace();
        }
      }
    }
  }

  public static ProviderDeploymentContributor getProviderContributor( String role, String name ) {
    ProviderDeploymentContributor contributor = null;
    Map<String,ProviderDeploymentContributor> nameMap = PROVIDER_CONTRIBUTOR_MAP.get( role );
    if( nameMap != null ) {
      if( name != null ) {
        contributor = nameMap.get( name );
      } else if ( !nameMap.isEmpty() ) {
        contributor = nameMap.values().iterator().next();
      }
    }
    return contributor;
  }

  public static ServiceDeploymentContributor getServiceContributor( String role, String name ) {
    ServiceDeploymentContributor contributor = null;
    Map<String,ServiceDeploymentContributor> nameMap = SERVICE_CONTRIBUTOR_MAP.get( role );
    if( nameMap != null ) {
      if( name == null ) {
        contributor = nameMap.values().iterator().next();
      } else if ( !nameMap.isEmpty() ) {
        contributor = nameMap.get( name );
      }
    }
    return contributor;
  }

  private static void finalize(
      DeploymentContext context,
      Map<String,List<ProviderDeploymentContributor>> providers,
      Map<String,List<ServiceDeploymentContributor>> services ) {
    try {
      // Write the gateway descriptor (gateway.xml) into the war.
      StringWriter writer = new StringWriter();
      GatewayDescriptorFactory.store( context.getGatewayDescriptor(), "xml", writer );
      context.getWebArchive().addAsWebInfResource(
          new StringAsset( writer.toString() ),
          GatewayServlet.GATEWAY_DESCRIPTOR_LOCATION_DEFAULT );

      // Set the location of the gateway descriptor as a servlet init param.
      ServletType<WebAppDescriptor> servlet = findServlet( context, context.getTopology().getName() );
      servlet.createInitParam()
          .paramName( GatewayServlet.GATEWAY_DESCRIPTOR_LOCATION_PARAM )
          .paramValue( GatewayServlet.GATEWAY_DESCRIPTOR_LOCATION_DEFAULT );

      for( String role : providers.keySet() ) {
        for( ProviderDeploymentContributor contributor : providers.get( role ) ) {
          try {
            contributor.finalizeContribution( context );
          } catch( Exception e ) {
            //TODO: I18N message.
            e.printStackTrace();
          }
        }
      }
      for( String role : services.keySet() ) {
        for( ServiceDeploymentContributor contributor : services.get( role ) ) {
          try {
            contributor.finalizeContribution( context );
          } catch( Exception e ) {
            //TODO: I18N message.
            e.printStackTrace();
          }
        }
      }

      // Write the web.xml into the war.
      Asset webXmlAsset = new StringAsset( context.getWebAppDescriptor().exportAsString() );
      context.getWebArchive().setWebXML( webXmlAsset );

    } catch ( IOException e ) {
      throw new RuntimeException( e );
    }
  }

  public static ServletType<WebAppDescriptor> findServlet( DeploymentContext context, String name ) {
    List<ServletType<WebAppDescriptor>> servlets = context.getWebAppDescriptor().getAllServlet();
    for( ServletType<WebAppDescriptor> servlet : servlets ) {
      if( name.equals( servlet.getServletName() ) ) {
        return servlet;
      }
    }
    return null;
  }  
  
  private static void loadServiceContributors() {
    Set<ServiceDeploymentContributor> set = new HashSet<ServiceDeploymentContributor>();
    Map<String,Map<String,ServiceDeploymentContributor>> roleMap
        = new HashMap<String,Map<String,ServiceDeploymentContributor>>();

    ServiceLoader<ServiceDeploymentContributor> loader = ServiceLoader.load( ServiceDeploymentContributor.class );
    Iterator<ServiceDeploymentContributor> contributors = loader.iterator();
    while( contributors.hasNext() ) {
      ServiceDeploymentContributor contributor = contributors.next();
      if( contributor.getName() == null ) {
        log.ignoringServiceContributorWithMissingName( contributor.getClass().getName() );
        continue;
      }
      if( contributor.getRole() == null ) {
        log.ignoringServiceContributorWithMissingRole( contributor.getClass().getName() );
        continue;
      }
      set.add( contributor );
      Map nameMap = roleMap.get( contributor.getRole() );
      if( nameMap == null ) {
        nameMap = new HashMap<String,ServiceDeploymentContributor>();
        roleMap.put( contributor.getRole(), nameMap );
      }
      nameMap.put( contributor.getName(), contributor );
    }
    //SERVICE_CONTRIBUTORS = set;
    SERVICE_CONTRIBUTOR_MAP = roleMap;
  }

  private static void loadProviderContributors() {
    Set<ProviderDeploymentContributor> set = new HashSet<ProviderDeploymentContributor>();
    Map<String,Map<String,ProviderDeploymentContributor>> roleMap
        = new HashMap<String,Map<String,ProviderDeploymentContributor>>();

    ServiceLoader<ProviderDeploymentContributor> loader = ServiceLoader.load( ProviderDeploymentContributor.class );
    Iterator<ProviderDeploymentContributor> contributors = loader.iterator();
    while( contributors.hasNext() ) {
      ProviderDeploymentContributor contributor = contributors.next();
      if( contributor.getName() == null ) {
        log.ignoringProviderContributorWithMissingName( contributor.getClass().getName() );
        continue;
      }
      if( contributor.getRole() == null ) {
        log.ignoringProviderContributorWithMissingRole( contributor.getClass().getName() );
        continue;
      }
      set.add( contributor );
      Map nameMap = roleMap.get( contributor.getRole() );
      if( nameMap == null ) {
        nameMap = new HashMap<String,ProviderDeploymentContributor>();
        roleMap.put( contributor.getRole(), nameMap );
      }
      nameMap.put( contributor.getName(), contributor );
    }
    PROVIDER_CONTRIBUTORS = set;
    PROVIDER_CONTRIBUTOR_MAP = roleMap;
  }

  static ProviderDeploymentContributor getProviderContributor(
      Map<String,List<ProviderDeploymentContributor>> providers, String role, String name ) {
    ProviderDeploymentContributor contributor = null;
    if( name == null ) {
      List<ProviderDeploymentContributor> list = providers.get( role );
      if( list != null && !list.isEmpty() ) {
        contributor = list.get( 0 );
      }
    } else {
      contributor = getProviderContributor( role, name );
    }
    return contributor;
  }

  static ServiceDeploymentContributor getServiceContributor(
      Map<String,List<ServiceDeploymentContributor>> services, String role, String name ) {
    ServiceDeploymentContributor contributor = null;
    if( name == null ) {
      List<ServiceDeploymentContributor> list = services.get( role );
      if( !list.isEmpty() ) {
        contributor = list.get( 0 );
      }
    } else {
      contributor = getServiceContributor( role, name );
    }
    return contributor;
  }

}