/**
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.adsddl.it;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.InvalidNameException;
import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;

import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceObjectFlags;
import net.tirasa.adsddl.ntsd.data.AceRights;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.controls.SDFlagsControl;
import net.tirasa.adsddl.ntsd.utils.GUID;
import net.tirasa.adsddl.ntsd.utils.NumberFacility;
import net.tirasa.adsddl.ntsd.utils.SDDLHelper;
import net.tirasa.adsddl.ntsd.utils.Hex;
import org.junit.Assert;
import org.junit.Test;

public class AllTest extends AbstractTest {

	private static final long serialVersionUID = 1L;

	@Test
	public void test() {

		try {

			log.info("Creating computer...");
			createComputer();
			
			log.info("Searching for computer...");
			isComputerExists();
			
			log.info("Setting computer permissions...");
			setNtSecurityDescriptor();
			
			log.info("Deleting computer...");
			deleteComputer();
			
			log.info("Test successfully complete");

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private void createComputer() throws Exception {

		Name ou = new CompositeName().add("OU=TestOU,DC=corp,DC=contoso,DC=com");//ouDN
		DirContext ctxOU = (DirContext)ctx.lookup(ou);
		
		Name comp = new CompositeName().add("cn=" + "computerFoo");
		
		// Create attributes to be associated with the new context
		Attributes attrs = new BasicAttributes(true); // case-ignore
		
		attrs.put("objectclass", "computer");
		attrs.put("ou", "TestOU");
		attrs.put("sAMAccountName", "computerFoo");
	      
		Attribute objclass = new BasicAttribute("objectclass");
		objclass.add("top");
		objclass.add("person");
		objclass.add("organizationalPerson");
		objclass.add("user");
		objclass.add("computer");
		attrs.put(objclass);

		// Create the context
		ctxOU.createSubcontext(comp, attrs);
		
	}
	
	private void setNtSecurityDescriptor() throws Exception {
		final SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setReturningAttributes(new String[] { "nTSecurityDescriptor" });

		ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });
		
		NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

		if (!results.hasMore()) {
			Assert.fail();
		}

		SearchResult res = results.next();
		final String dn = res.getNameInNamespace();

		final byte[] orig = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();

		SDDL sddl = new SDDL(orig);

		results.close();

		final Attribute ntSecurityDescriptor = new BasicAttribute("ntSecurityDescriptor",
				setAce(sddl, true).toByteArray());

		final ModificationItem[] mods = new ModificationItem[1];
		mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, ntSecurityDescriptor);

		ctx.modifyAttributes(dn, mods);

		ctx.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });
		
//		for (Control control: new Control[] { new SDFlagsControl(0x00000001 + 0x00000002 + 0x00000004) }) {
//			System.out.println("Control is:\t"+control);
//		}
		
		results = ctx.search(baseContext, searchFilter, controls);

		if (!results.hasMore()) {
			Assert.fail();
		}

		res = results.next();
		assertEquals(dn, res.getNameInNamespace());

		final byte[] changed = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
		assertFalse(Arrays.equals(orig, changed));

		sddl = new SDDL(changed);
		assertNotNull(sddl.getDacl());
//		assertNotNull(sddl.getOwner());
//		assertNotNull(sddl.getGroup());
		// assertNotNull(sddl.getSacl());

		final List<ACE> found = new ArrayList<>();

	}

	private SDDL setAce(final SDDL sddl, final boolean cannot) {
		// final AceType type = cannot ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE :
		// AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;
		final AceType type = AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;

		ACE ace = ACE.newInstance(type);

		ace.setType(AceType.ACCESS_ALLOWED_ACE_TYPE);
		ace.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.GA));

		SID sid = SID.newInstance(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 });

		sid.addSubAuthority(NumberFacility.getBytes(0x15));
		
		

		sid.addSubAuthority(new byte[] { (byte) 0x8E, 0x68, (byte) 0xBD, (byte) 0x88 });
		sid.addSubAuthority(new byte[] { 0x13, 0x47, 0x44, (byte) 0x9F });
		sid.addSubAuthority(new byte[] { (byte) 0xC9, (byte) 0xD8, 0x0A, (byte) 0xF1 });
		sid.addSubAuthority(new byte[] { 0x00, 0x00, 0x04, 0x57 });

		ace.setSid(sid);
		sddl.getDacl().getAces().add(ace);

		return sddl;
	}
	
	private void isComputerExists() throws Exception {
		final SearchControls controls = new SearchControls();
		controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		controls.setReturningAttributes(new String[] { "cn" });

		NamingEnumeration<SearchResult> results = ctx.search(baseContext, searchFilter, controls);

		if (!results.hasMore()) {
			Assert.fail();
		}

		SearchResult res = results.next();
		
		log.info("Found: "+res.getNameInNamespace());
		
		results.close();

	}
	
	private void deleteComputer() throws NamingException {
		
		ctx.destroySubcontext("CN=computerFoo,OU=TestOU,DC=corp,DC=contoso,DC=com");
		
	}
	
	
}
