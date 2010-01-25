//: "The contents of this file are subject to the Mozilla Public License
//: Version 1.1 (the "License"); you may not use this file except in
//: compliance with the License. You may obtain a copy of the License at
//: http://www.mozilla.org/MPL/
//:
//: Software distributed under the License is distributed on an "AS IS"
//: basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//: License for the specific language governing rights and limitations
//: under the License.
//:
//: The Original Code is Guanxi (http://www.guanxi.uhi.ac.uk).
//:
//: The Initial Developer of the Original Code is Alistair Young alistair@codebrane.com
//: All Rights Reserved.
//:

package org.guanxi.sp.guard;

/**
 * Encapsulates information about profile based access to a resource
 *
 * @author alistair
 */
public class Profile {
  /** The name of the profile */
  public String name = null;
  /** The binding to use with the profile */
  public String binding = null;
  /** The entityID of the actor who is accessing the resource */
  public String entityID = null;
  /** The path of the resource being accessed */
  public String resourceURI = null;
}
