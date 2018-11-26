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
package org.apache.knox.gateway.services.security.impl;

import org.apache.knox.gateway.i18n.GatewaySpiMessages;
import org.apache.knox.gateway.i18n.messages.MessagesFactory;
import org.apache.knox.gateway.services.security.KeystoreServiceException;
import org.apache.knox.gateway.services.security.MasterService;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

public class BaseKeystoreService {
  private static final GatewaySpiMessages LOG = MessagesFactory.get(GatewaySpiMessages.class);

  public static final String CREDENTIAL_STORE_TYPE = "JCEKS";
  public static final String KEYSTORE_TYPE = "JKS";

  protected MasterService masterService;
  protected String keyStoreDir;

  private static KeyStore loadKeyStore(final File keyStoreFile, final char[] masterPassword, String storeType)
      throws CertificateException, IOException, KeyStoreException,
                 NoSuchAlgorithmException {
    final KeyStore keyStore = KeyStore.getInstance(storeType);
    if (keyStoreFile.exists()) {
      try (FileInputStream input = new FileInputStream(keyStoreFile)) {
        keyStore.load(input, masterPassword);
      }
    } else {
      keyStore.load(null, masterPassword);
    }

    return keyStore;
  }

  private static FileOutputStream createKeyStoreFile(String fileName) throws IOException {
    File file = new File(fileName);
    if (file.exists()) {
      if (file.isDirectory() || !file.canWrite()) {
        throw new IOException(file.getAbsolutePath());
      }
    } else {
      File dir = file.getParentFile();
      if (!dir.exists() && !dir.mkdirs()) {
        throw new IOException(file.getAbsolutePath());
      }
    }
    return new FileOutputStream(file);
  }

  protected void createKeystore(String filename, String keystoreType) throws KeystoreServiceException {
    try (FileOutputStream out = createKeyStoreFile(filename)) {
      KeyStore ks = KeyStore.getInstance(keystoreType);
      ks.load(null, null);
      ks.store(out, masterService.getMasterSecret());
    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
      LOG.failedToCreateKeystore(filename, keystoreType, e);
      throw new KeystoreServiceException(e);
    }
  }

  protected boolean isKeystoreAvailable(final File keyStoreFile, String storeType) throws KeyStoreException, IOException {
    if (keyStoreFile.exists()) {
      try (FileInputStream input = new FileInputStream(keyStoreFile)) {
        final KeyStore keyStore = KeyStore.getInstance(storeType);
        keyStore.load(input, masterService.getMasterSecret());
        return true;
      } catch (NoSuchAlgorithmException | CertificateException e) {
        LOG.failedToLoadKeystore(keyStoreFile.getName(), storeType, e);
      } catch (IOException | KeyStoreException e) {
        LOG.failedToLoadKeystore(keyStoreFile.getName(), storeType, e);
        throw e;
      }
    }
    return false;
  }

  protected KeyStore getKeystore(final File keyStoreFile, String storeType) throws KeystoreServiceException {
    KeyStore credStore;
    try {
      credStore = loadKeyStore(keyStoreFile, masterService.getMasterSecret(), storeType);
    } catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | IOException e) {
      LOG.failedToLoadKeystore(keyStoreFile.getName(), storeType, e);
      throw new KeystoreServiceException(e);
    }
    return credStore;
  }

  public BaseKeystoreService() {
    super();
  }

  protected void addCredential(String alias, String value, KeyStore ks) {
    if (ks != null) {
      try {
        final Key key = new SecretKeySpec(value.getBytes(StandardCharsets.UTF_8), "AES");
        ks.setKeyEntry(alias, key, masterService.getMasterSecret(), null);
      } catch (KeyStoreException e) {
        LOG.failedToAddCredential(e);
      }
    }
  }

  public void removeCredential(String alias, KeyStore ks) {
    if (ks != null) {
      try {
        if (ks.containsAlias(alias)) {
          ks.deleteEntry(alias);
        }
      } catch (KeyStoreException e) {
        LOG.failedToRemoveCredential(e);
      }
    }
  }

  protected char[] getCredential(String alias, char[] credential, KeyStore ks) {
    if (ks != null) {
      try {
        credential = new String(ks.getKey(alias, masterService.getMasterSecret()).getEncoded(), StandardCharsets.UTF_8).toCharArray();
      } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
        LOG.failedToGetCredential(e);
      }
    }
    return credential;
  }

  protected void writeKeystoreToFile(final KeyStore keyStore, final File file)
      throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
    // TODO: backup the keystore on disk before attempting a write and restore on failure
    try (final FileOutputStream out = new FileOutputStream(file)) {
      keyStore.store(out, masterService.getMasterSecret());
    }
  }

  public void setMasterService(MasterService ms) {
    this.masterService = ms;
  }
}
