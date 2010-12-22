package org.jboss.security.authorization.modules;
 
import javax.security.auth.Subject;

import org.jboss.logging.Logger;
import org.jboss.security.authorization.AuthorizationModule;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.Resource;
import org.jboss.security.identity.RoleGroup;

//$Id$

/**
 *  Delegate for Authorization Module
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Jun 19, 2006 
 *  @version $Revision$
 */
public abstract class AuthorizationModuleDelegate
{
   protected static Logger log = Logger.getLogger(AuthorizationModuleDelegate.class);
   protected boolean trace = false;
   
   /**
    * Policy Registration Manager Injected
    */
   protected PolicyRegistration policyRegistration = null; 
   
   /**
    * @see AuthorizationModule#authorize(Resource)
    * @param resource
    * @param subject Authenticated Subject
    * @param role RoleGroup
    * @return
    */
   public abstract int authorize(Resource resource, Subject subject, RoleGroup role); 
   
   /**
    * Set the PolicyRegistration manager 
    * Will be used to query for the policies
    * @param authzManager
    */
   public void setPolicyRegistrationManager(PolicyRegistration pm)
   {
      this.policyRegistration = pm;
   } 
}
