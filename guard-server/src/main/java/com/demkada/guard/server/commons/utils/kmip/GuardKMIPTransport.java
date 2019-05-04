/**
 * GuardKMIPTransport.java
 * -----------------------------------------------------------------
 *     __ __ __  ___________ 
 *    / //_//  |/  /  _/ __ \	  .--.
 *   / ,<  / /|_/ // // /_/ /	 /.-. '----------.
 *  / /| |/ /  / // // ____/ 	 \'-' .--"--""-"-'
 * /_/ |_/_/  /_/___/_/      	  '--'
 * 
 * -----------------------------------------------------------------
 * Description:
 * The GuardKMIPTransport provides the needful
 * flexibility for the interchangeability of the Transport Layer on 
 * the client side. It offers one method to send a message and three
 * methods to set dynamically loaded parameters. 
 *
 * @author     Stefanie Meile <stefaniemeile@gmail.com>
 * @author     Michael Guster <michael.guster@gmail.com>
 * @org.       NTB - University of Applied Sciences Buchs, (CH)
 * @copyright  Copyright � 2013, Stefanie Meile, Michael Guster
 * @license    Simplified BSD License (see LICENSE.TXT)
 * @version    1.0, 2013/08/09
 * @since      Class available since Release 1.0
 *
 * 
 */

package com.demkada.guard.server.commons.utils.kmip;

import ch.ntb.inf.kmip.stub.transport.KMIPStubTransportLayerInterface;

public interface GuardKMIPTransport extends KMIPStubTransportLayerInterface {

	public void setPort(int port);
	
	/**
	 *
	 * Alias du certificat contenu dans le keystore et utilisé pour la communication avec le serveur KMIP .
	 *
	 * @param aliasCertificateKeySecure :  alias défini dans le fichier kmip.properties.
	 */
	public void setKeystoreCertificateAlias(String aliasCertificateKeySecure);

}
