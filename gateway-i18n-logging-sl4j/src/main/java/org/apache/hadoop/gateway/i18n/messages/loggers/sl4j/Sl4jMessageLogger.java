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
package org.apache.hadoop.gateway.i18n.messages.loggers.sl4j;

import org.apache.hadoop.gateway.i18n.messages.MessageLevel;
import org.apache.hadoop.gateway.i18n.messages.MessageLogger;
import org.slf4j.Logger;

public class Sl4jMessageLogger implements MessageLogger {

  private Logger logger;

  Sl4jMessageLogger( Logger logger ) {
    this.logger = logger;
  }

  @Override
  public boolean isLoggable( MessageLevel level ) {
    switch( level ) {
      case FATAL: return logger.isErrorEnabled();
      case ERROR: return logger.isErrorEnabled();
      case WARN: return logger.isWarnEnabled();
      case INFO: return logger.isInfoEnabled();
      case DEBUG: return logger.isDebugEnabled();
      case TRACE: return logger.isTraceEnabled();
      default: return false;
    }
  }

  @Override
  public void log( MessageLevel messageLevel, String messageId, String messageText, Throwable throwable ) {
    switch( messageLevel ) {
      case FATAL:
      case ERROR:
        if( throwable == null )
          logger.error( messageText );
        else
          logger.error( messageText, throwable );
        break;
      case WARN:
        if( throwable == null )
          logger.warn( messageText );
        else
          logger.warn( messageText, throwable );
        break;
      case INFO:
        if( throwable == null )
          logger.info( messageText );
        else
          logger.info( messageText, throwable );
        break;
      case DEBUG:
        if( throwable == null )
          logger.debug( messageText );
        else
          logger.debug( messageText, throwable );
        break;
      case TRACE:
        if( throwable == null )
          logger.trace( messageText );
        else
          logger.trace( messageText, throwable );
        break;
    }
  }

}