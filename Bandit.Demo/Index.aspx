<%@ Page Language="C#" AutoEventWireup="true" CodeBehind="Index.aspx.cs" Inherits="Bandit.Demo.Index" %>

<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Example Page</title>
</head>
<body>
    This is a site protected by Bandit.
    <ul>
        <li><a href="Index.aspx/?BanditTest=1">?Bandit.Test=1 - Disable trusted IP exclusion.</a></li>
        <li><a href="Index.aspx/?BanditClear=1">?Bandit.Clear=1 - Clear bans</a></li>
    </ul>
</body>
</html>
