/*
 * Copyright (c) 1990-2012 kopiLeft Development SARL, Bizerte, Tunisia
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

package org.kopi.ebics.xml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.kopi.ebics.exception.EbicsException;
import org.kopi.ebics.session.EbicsSession;
import org.kopi.ebics.utils.Utils;

/**
 * The <code>HPBRequestElement</code> is the element to be sent when
 * a HPB request is needed to retrieve the bank public keys
 *
 *
 */
public class HPBRequestElement extends DefaultEbicsRootElement {
    private static final Logger log = LoggerFactory.getLogger(HPBRequestElement.class);

  /**
   * Constructs a new HPB Request element.
   * @param session the current ebics session.
   */
  public HPBRequestElement(EbicsSession session) {
    super(session);
  }

  @Override
  public String getName() {
    return "HPBRequest.xml";
  }

  @Override
  public void build() throws EbicsException {
    log.info("[DEBUG-LOG] Building HPB Request");
    var user = session.getUser();
    log.info("[DEBUG-LOG] Used Private Keys for HPB:");
    if (user.getA005PrivateKey() != null) {
        log.info("[DEBUG-LOG] Private Key A (PEM):\n{}", Utils.formatPEM("PRIVATE KEY", user.getA005PrivateKey().getEncoded()));
        log.info("[DEBUG-LOG] SHA-256 Cert A: {}", Utils.sha256(user.getA005Certificate()));
    }
    if (user.getX002PrivateKey() != null) {
        log.info("[DEBUG-LOG] Private Key X (PEM):\n{}", Utils.formatPEM("PRIVATE KEY", user.getX002PrivateKey().getEncoded()));
        log.info("[DEBUG-LOG] SHA-256 Cert X: {}", Utils.sha256(user.getX002Certificate()));
    }
    if (user.getE002PrivateKey() != null) {
        log.info("[DEBUG-LOG] Private Key E (PEM):\n{}", Utils.formatPEM("PRIVATE KEY", user.getE002PrivateKey().getEncoded()));
        log.info("[DEBUG-LOG] SHA-256 Cert E: {}", Utils.sha256(user.getE002Certificate()));
    }

    noPubKeyDigestsRequest = new NoPubKeyDigestsRequestElement(session);
    noPubKeyDigestsRequest.build();
    var signedInfo = new SignedInfo(session.getUser(), noPubKeyDigestsRequest.getDigest());
    signedInfo.build();
    noPubKeyDigestsRequest.setAuthSignature(signedInfo.getSignatureType());
    var signature = signedInfo.sign(noPubKeyDigestsRequest.toByteArray());
    noPubKeyDigestsRequest.setSignatureValue(signature);
  }

  @Override
  public byte[] toByteArray() {
    return noPubKeyDigestsRequest.toByteArray();
  }

  @Override
  public void validate() throws EbicsException {
    noPubKeyDigestsRequest.validate();
  }

  // --------------------------------------------------------------------
  // DATA MEMBERS
  // --------------------------------------------------------------------

  private NoPubKeyDigestsRequestElement		noPubKeyDigestsRequest;
  private static final long 			serialVersionUID = -5565390370996751973L;
}
