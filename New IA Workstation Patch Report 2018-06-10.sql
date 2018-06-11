-- NEW IA Workstation Report
-- Currently Set for Pre Patch Months Cycle
--Do I add OS Critical?

select 
C.displayname 
,coalesce(C.type, 'Unknown') [Type]
,coalesce(convert(varchar,C.valastscandate), 'Unknown') [Last Vul Scan]
,coalesce(convert(varchar,C.RecordDate), 'Unknown') [Added To LANDesk]
,coalesce(convert(varchar,C.installdate), 'Unknown') [OS Build Date]
,coalesce(convert(varchar,C.Lastbootuptime), 'Unknown') [Last Boot Time]
,coalesce(c.total,0) [# of Missing Patches Total]
,coalesce(c.lastmonth,0) [# of Missing Published last month]
,coalesce(c.prevyear,0) [# of Missing Published in past year]

,coalesce(adx.domain, 'Unknown') [Domain]
,coalesce(c.ComputerLocation, 'Unknown') [ComputerLocation]
,coalesce(adx.OU, 'Unknown') [OU]
,coalesce(adx.CityID, 'Unknown') [City]
,coalesce(adx.SiteID, 'Unknown') [Site]
,coalesce(adx.BrandID, 'Unknown') [Brand]
,[OpCo] =
	Case
		When OU like 'Domain Controllers' Then 'Domain Controllers'
		When OU like 'GIS' Then 'IPG'
		Else coalesce(adx.OpCode, 'Unknown')
	End



FROM 

(-- Start C

	--NALA
	(select c.displayname, c.type, c.valastscandate, c.computerlocation, Occurrence.NumberDetected as Total, lastmonth.NumberDetected as lastmonth, prevyear.NumberDetected as prevyear, 
	c.recorddate, osnt.installdate, osnt.lastbootuptime, c.deviceID
	FROM   OMA010.LDNALA_Wks_Core.dbo.computer C  (nolock) 
	left outer join OMA010.LDNALA_Wks_Core.dbo.osnt osnt (nolock)
	on c.computer_idn = osnt.computer_idn
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   OMA010.LDNALA_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System' 
								   and PublishDate <= EOMONTH(getdate(),-2)
							GROUP  BY b.computer_idn) Occurrence 
		ON Occurrence.computer_idn = C.computer_idn
	--Missing Last Month
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   OMA010.LDNALA_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System'
							   		and PublishDate > EOMONTH(getdate(),-3) --newer than month before last
									and PublishDate <= EOMONTH(getdate(),-2) 
							GROUP  BY b.computer_idn) lastmonth 
		ON lastmonth.computer_idn = C.computer_idn
	--Missing Last year
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   OMA010.LDNALA_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System'
							   		and PublishDate > EOMONTH(getdate(),-14) --published in the 12 months
									and PublishDate <= EOMONTH(getdate(),-3) 
							GROUP  BY b.computer_idn) prevyear 
		ON prevyear.computer_idn = C.computer_idn
	where c.deviceid != 'Unassigned' and displayname is not null)
	--END NALA

	UNION

	--EMEA
	(select c.displayname, c.type, c.valastscandate, c.computerlocation, Occurrence.NumberDetected as Total, lastmonth.NumberDetected as lastmonth, prevyear.NumberDetected as prevyear, 
	c.recorddate, osnt.installdate, osnt.lastbootuptime, c.deviceID
	FROM   LDN010.LDEMEA_Wks_Core.dbo.computer C  (nolock) 
	left outer join LDN010.LDEMEA_Wks_Core.dbo.osnt osnt (nolock)
	on c.computer_idn = osnt.computer_idn
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   LDN010.LDEMEA_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System' 
								   and PublishDate <= EOMONTH(getdate(),-2)
							GROUP  BY b.computer_idn) Occurrence 
		ON Occurrence.computer_idn = C.computer_idn
	--Missing Last Month
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   LDN010.LDEMEA_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System'
							   		and PublishDate > EOMONTH(getdate(),-3) --newer than month before last
									and PublishDate <= EOMONTH(getdate(),-2) 
							GROUP  BY b.computer_idn) lastmonth 
		ON lastmonth.computer_idn = C.computer_idn
	--Missing Last year
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   LDN010.LDEMEA_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System'
							   		and PublishDate > EOMONTH(getdate(),-14) --published in the 12 months
									and PublishDate <= EOMONTH(getdate(),-3) 
							GROUP  BY b.computer_idn) prevyear 
		ON prevyear.computer_idn = C.computer_idn
	where c.deviceid != 'Unassigned' and displayname is not null)
	--END EMEA

	UNION

	--HKG
	(select c.displayname, c.type, c.valastscandate, c.computerlocation, Occurrence.NumberDetected as Total, lastmonth.NumberDetected as lastmonth, prevyear.NumberDetected as prevyear, 
	c.recorddate, osnt.installdate, osnt.lastbootuptime, c.deviceID
	FROM   HKG001.LDHKG_Wks_Core.dbo.computer C  (nolock) 
	left outer join HKG001.LDHKG_Wks_Core.dbo.osnt osnt (nolock)
	on c.computer_idn = osnt.computer_idn
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   HKG001.LDHKG_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System' 
								   and PublishDate <= EOMONTH(getdate(),-2)
							GROUP  BY b.computer_idn) Occurrence 
		ON Occurrence.computer_idn = C.computer_idn
	--Missing Last Month
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   HKG001.LDHKG_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System'
							   		and PublishDate > EOMONTH(getdate(),-3) --newer than month before last
									and PublishDate <= EOMONTH(getdate(),-2) 
							GROUP  BY b.computer_idn) lastmonth 
		ON lastmonth.computer_idn = C.computer_idn
	--Missing Last year
	LEFT OUTER JOIN (SELECT b.computer_idn, 
								   Count(b.computer_idn) AS NumberDetected 
							FROM   HKG001.LDHKG_Wks_Core.dbo.cvdetectedv b  (nolock) 
							WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
								   AND b.vulseverity = 'Critical' 
								   AND b.category = 'Operating System'
							   		and PublishDate > EOMONTH(getdate(),-14) --published in the 12 months
									and PublishDate <= EOMONTH(getdate(),-3) 
							GROUP  BY b.computer_idn) prevyear 
		ON prevyear.computer_idn = C.computer_idn
	where c.deviceid != 'Unassigned' and displayname is not null)
	--END HKG
) C --END C

left join ( select hostname, Domain, OU, CityID, SiteID, BrandID, OpCode  from omaedcapp249.shareddev.dbo.vw_adcomputersexpanded
			where  [Days Since Last Contact] < 60 and EnabledStatus = 'Enabled'
			) adx
on c.displayname = adx.hostname

Order by displayname