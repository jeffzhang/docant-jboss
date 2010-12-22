package org.jboss.security.authorization.modules.ejb;

import java.lang.reflect.Method;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.jacc.EJBMethodPermission;
import javax.security.jacc.EJBRoleRefPermission;

import org.jboss.logging.Logger;
import org.jboss.security.authorization.AuthorizationContext;
import org.jboss.security.authorization.PolicyRegistration;
import org.jboss.security.authorization.Resource;
import org.jboss.security.authorization.ResourceKeys;
import org.jboss.security.authorization.modules.AbstractJACCModuleDelegate;
import org.jboss.security.authorization.modules.AuthorizationModuleDelegate;
import org.jboss.security.authorization.resources.EJBResource;
import org.jboss.security.identity.Role;
import org.jboss.security.identity.RoleGroup;
 

//$Id$

/**
 *  Authorization Module delegate that deals with the authorization decisions
 *  for the EJB Layer
 *  @author <a href="mailto:Anil.Saldhana@jboss.org">Anil Saldhana</a>
 *  @since  Jul 6, 2006 
 *  @version $Revision$
 */
public class EJBJACCPolicyModuleDelegate extends AbstractJACCModuleDelegate
{  
   private String ejbName = null;
   private Method ejbMethod = null; 
   private String methodInterface = null;
   private CodeSource ejbCS = null;
   private String roleName = null;  
   private Boolean roleRefCheck = Boolean.FALSE;  
   
   public EJBJACCPolicyModuleDelegate()
   {
      log = Logger.getLogger(getClass());
      trace = log.isTraceEnabled();
   }
   
   /**
    * @see AuthorizationModuleDelegate#authorize(Resource)
    */
   public int authorize(Resource resource, Subject callerSubject, RoleGroup role)
   {
      if(resource instanceof EJBResource == false)
         throw new IllegalArgumentException("resource is not an EJBResource");
      
      EJBResource ejbResource = (EJBResource) resource;
      
      //Get the context map
      Map<String,Object> map = resource.getMap();
      if(map == null)
         throw new IllegalStateException("Map from the Resource is null");

      this.policyRegistration = (PolicyRegistration) map.get(ResourceKeys.POLICY_REGISTRATION);
      
      this.ejbCS = ejbResource.getCodeSource();
      this.ejbMethod = ejbResource.getEjbMethod();
      this.ejbName = ejbResource.getEjbName();
      this.methodInterface = ejbResource.getEjbMethodInterface();
      
      //isCallerInRole checks
      this.roleName = (String)map.get(ResourceKeys.ROLENAME); 
      
      this.roleRefCheck = (Boolean)map.get(ResourceKeys.ROLEREF_PERM_CHECK);
      if(this.roleRefCheck == Boolean.TRUE)
         return checkRoleRef(callerSubject, role);
      else
         return process(callerSubject, role);
   } 
   
   //Private Methods
   /**
    * Process the request
    * @param request
    * @param sc
    * @return
    */
   private int process(Subject callerSubject, Role role) 
   {  
      EJBMethodPermission methodPerm = 
         new EJBMethodPermission(ejbName, methodInterface, ejbMethod); 
      boolean policyDecision = checkWithPolicy(methodPerm, callerSubject, role); 
      if( policyDecision == false )
      {
         String msg = "Denied: "+methodPerm+", caller=" + callerSubject+", role="+role;
         if(trace)
            log.trace("EJB Jacc Delegate:"+msg);  
      }  
      return policyDecision ? AuthorizationContext.PERMIT : AuthorizationContext.DENY;
   }
   
   private int checkRoleRef(Subject callerSubject, RoleGroup callerRoles)
   { 
      //This has to be the EJBRoleRefPermission  
      EJBRoleRefPermission ejbRoleRefPerm = new EJBRoleRefPermission(ejbName,roleName); 
      boolean policyDecision = checkWithPolicy(ejbRoleRefPerm, callerSubject, callerRoles); 
      if( policyDecision == false )
      {
         String msg = "Denied: "+ejbRoleRefPerm+", caller=" + callerSubject;
         if(trace)
            log.trace("EJB Jacc Delegate:"+msg);  
      }  
      return policyDecision ? AuthorizationContext.PERMIT : AuthorizationContext.DENY; 
   }
   
   private boolean checkWithPolicy(Permission ejbPerm, Subject subject, Role role)
   {
      Principal[] principals = this.getPrincipals(subject, role);  
      ProtectionDomain pd = new ProtectionDomain (ejbCS, null, null, principals);
      return Policy.getPolicy().implies(pd, ejbPerm); 
   }
}
