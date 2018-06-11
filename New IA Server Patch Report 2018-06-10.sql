--New Server Compliance for IA with lastMonth and prevYear
-- This is run in June before patching, so last month is april ( > 33, <= -2) and last 12 is april to april

(SELECT 
                C.displayname, 
                coalesce(C.type, 'Unknown') [Type], 
				coalesce(convert(varchar,C.valastscandate), 'Unknown') [Last Vul Scan],
				coalesce(convert(varchar,C.RecordDate), 'Unknown') [Added To LANDesk],
				coalesce(convert(varchar,C.installdate), 'Unknown') [OS Build Date],
				coalesce(convert(varchar,C.Lastbootuptime), 'Unknown') [Last Boot Time],
			    coalesce(c.total,0) [# of Missing Patches Total],
				coalesce(c.lastmonth,0) [# of Missing Published last month],
				coalesce(c.prevyear,0) [# of Missing Published in past year],
				-- This 
				--[Patch Compliant] = 
				--Case
				--	When c.NumberDetected > 4 Then 'Not Compliant'
				--	When (c.NumberDetected is NULL) or (c.NumberDetected <= 4) Then 'Compliant'  /* FUDGE FACTOR */
				--	Else 'Unknown'
				--End,
				coalesce(adx.domain, 'Unknown') [Domain],
				coalesce(c.ComputerLocation, 'Unknown') [ComputerLocation]
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
				--,coalesce(adx.OpCode, 'Unknown') [OpCo]
				,coalesce(c.server_location, '') [Data Center Tag]
				--,coalesce(c.ResponsibleTeam, '') [ResponsibleTeam]
			--,[PatchResponsibility] =
	--Case
	--	When c.Server_Location is not null or c.ResponsibleTeam = 'AD Team' or c.ResponsibleTeam = 'Messaging'
	--		Then 'IPG EIS Managed'
	--	When c.Server_Location is null and c.ResponsibleTeam = 'FSO' 
	--		Then 'EIS Managed for FSO'
	--	When c.Server_Location is null and c.ResponsibleTeam is null
	--		Then 'Managed by Local FSO'
	--	Else 'Unknown'
	--End 
FROM 

--Full UNION
--Start C
(

(--NEW CORE
select c.displayname, c.type, c.valastscandate, c.computerlocation, Occurrence.NumberDetected as Total, lastmonth.NumberDetected as lastmonth, prevyear.NumberDetected as prevyear, 
c.recorddate, osnt.installdate, osnt.lastbootuptime, loc.server_location --,-sp.ResponsibleTeam, c.deviceID
FROM   OMA020.[LDGbl_Srv_Core].dbo.computer C  (nolock) 
left outer join OMA020.[LDGbl_Srv_Core].dbo.osnt osnt (nolock)
on c.computer_idn = osnt.computer_idn
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   OMA020.[LDGbl_Srv_Core].dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System' 
							   and PublishDate <= EOMONTH(getdate(),-2)
                        GROUP  BY b.computer_idn) Occurrence 
	ON Occurrence.computer_idn = C.computer_idn
--Missing Last Month
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   OMA020.[LDGbl_Srv_Core].dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-3) --newer than month before last
								and PublishDate <= EOMONTH(getdate(),-2) 
                        GROUP  BY b.computer_idn) lastmonth 
	ON lastmonth.computer_idn = C.computer_idn
--Missing Last year
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   OMA020.[LDGbl_Srv_Core].dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-14) --published in the 12 months
								and PublishDate <= EOMONTH(getdate(),-3) 
                        GROUP  BY b.computer_idn) prevyear 
	ON prevyear.computer_idn = C.computer_idn
LEFT OUTER JOIN OMA020.[LDGbl_Srv_Core].dbo.IPG_Location loc
on c.computer_idn = loc.computer_idn
--LEFT OUTER JOIN OMA020.[LDGbl_Srv_Core].dbo.IPG_Tools_ServerPatching sp
--on c.Computer_Idn = sp.Computer_Idn
where c.deviceid != 'Unassigned' and displayname is not null
)  --end Gbl


UNION
-- OLD DBs except what's in new DB
		select b.* from (--start b
			select * from (--Start a
			-- NA
			(select c.displayname, c.type, c.valastscandate, c.computerlocation, Occurrence.NumberDetected as Total, lastmonth.NumberDetected as lastmonth, prevyear.NumberDetected as prevyear,
			c.recorddate, osnt.installdate, osnt.lastbootuptime, loc.server_location--, sp.ResponsibleTeam, c.deviceID
			FROM   OMA020.LDNALA_Srv_Core.dbo.computer C  (nolock) 
			left outer join OMA020.LDNALA_Srv_Core.dbo.osnt osnt (nolock)
			on c.computer_idn = osnt.computer_idn
			LEFT OUTER JOIN (SELECT b.computer_idn, 
										   Count(b.computer_idn) AS NumberDetected 
									FROM   OMA020.LDNALA_Srv_Core.dbo.cvdetectedv b  (nolock) 
									WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
										   --AND b.vulseverity = 'Critical' 
										   --AND b.category = 'Operating System' 
											and PublishDate <= EOMONTH(getdate(),-2) 
									GROUP  BY b.computer_idn) Occurrence 
				ON Occurrence.computer_idn = C.computer_idn
--Missing Last Month
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   OMA020.[LDNALA_Srv_Core].dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-3) --newer than month before last
								and PublishDate <= EOMONTH(getdate(),-2) 
                        GROUP  BY b.computer_idn) lastmonth 
	ON lastmonth.computer_idn = C.computer_idn
--Missing Last year
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   OMA020.[LDNALA_Srv_Core].dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-14) --published in the 12 months
								and PublishDate <= EOMONTH(getdate(),-3) 
                        GROUP  BY b.computer_idn) prevyear 
	ON prevyear.computer_idn = C.computer_idn				
			LEFT OUTER JOIN OMA020.LDNALA_Srv_Core.dbo.IPG_Location loc
			on c.computer_idn = loc.computer_idn
			--LEFT OUTER JOIN OMA020.LDNALA_Srv_Core.dbo.IPG_Tools_ServerPatching sp
			--on c.Computer_Idn = sp.Computer_Idn
			where c.deviceid != 'Unassigned' and displayname is not null)																			

			UNION

			--ENEA
			(select c.displayname, c.type, c.valastscandate, c.computerlocation, Occurrence.NumberDetected as Total, lastmonth.NumberDetected as lastmonth, prevyear.NumberDetected as prevyear,
			c.recorddate, osnt.installdate, osnt.lastbootuptime,  loc.server_location--, NULL as ResponsibleTeam, c.deviceID --sp.ResponsibleTeam
			FROM   LDN020.LDEMEA_Srv_Core.dbo.computer C  (nolock) 
			left outer join LDN020.LDEMEA_Srv_Core.dbo.osnt osnt (nolock)
			on c.computer_idn = osnt.computer_idn
			LEFT OUTER JOIN (SELECT b.computer_idn, 
										   Count(b.computer_idn) AS NumberDetected 
									FROM   LDN020.LDEMEA_Srv_Core.dbo.cvdetectedv b  (nolock) 
									WHERE  b.compliance_name = 'Yes'  and b.vultype = 'Vulnerability'
										   --AND b.vulseverity = 'Critical' 
										   --AND b.category = 'Operating System' 
											and PublishDate <= EOMONTH(getdate(),-2) 
									GROUP  BY b.computer_idn) Occurrence 
				ON Occurrence.computer_idn = C.computer_idn
--Missing Last Month
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM  LDN020.LDEMEA_Srv_Core.dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-3) --newer than month before last
								and PublishDate <= EOMONTH(getdate(),-2) 
                        GROUP  BY b.computer_idn) lastmonth 
	ON lastmonth.computer_idn = C.computer_idn
--Missing Last year
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   LDN020.LDEMEA_Srv_Core.dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-14) --published in the 12 months
								and PublishDate <= EOMONTH(getdate(),-3) 
                        GROUP  BY b.computer_idn) prevyear 
	ON prevyear.computer_idn = C.computer_idn
			LEFT OUTER JOIN LDN020.LDEMEA_Srv_Core.dbo.IPG_Location loc
			on c.computer_idn = loc.computer_idn
			where c.deviceid != 'Unassigned' and displayname is not null
			) -- END EMEA 
			

						UNION

			-- AP
			(select c.displayname, c.type, c.valastscandate, c.computerlocation, Occurrence.NumberDetected as Total, lastmonth.NumberDetected as lastmonth, prevyear.NumberDetected as prevyear,
			c.recorddate, osnt.installdate, osnt.lastbootuptime, loc.server_location--, NULL as ResponsibleTeam, c.deviceID --sp.ResponsibleTeam
			FROM   HKG002.LDHKG_Server_Core.dbo.computer C  (nolock) 
			left outer join HKG002.LDHKG_Server_Core.dbo.osnt osnt (nolock)
			on c.computer_idn = osnt.computer_idn
			LEFT OUTER JOIN (SELECT b.computer_idn, 
										   Count(b.computer_idn) AS NumberDetected 
									FROM   HKG002.LDHKG_Server_Core.dbo.cvdetectedv b  (nolock) 
									WHERE  b.compliance_name = 'Yes'  and b.vultype = 'Vulnerability'
										   --AND b.vulseverity = 'Critical' 
										   --AND b.category = 'Operating System' 
											and PublishDate <= EOMONTH(getdate(),-2) 
									GROUP  BY b.computer_idn) Occurrence 
				ON Occurrence.computer_idn = C.computer_idn
--Missing Last Month
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   HKG002.LDHKG_Server_Core.dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-3) --newer than month before last
								and PublishDate <= EOMONTH(getdate(),-2) 
                        GROUP  BY b.computer_idn) lastmonth 
	ON lastmonth.computer_idn = C.computer_idn
--Missing Last year
LEFT OUTER JOIN (SELECT b.computer_idn, 
                               Count(b.computer_idn) AS NumberDetected 
                        FROM   HKG002.LDHKG_Server_Core.dbo.cvdetectedv b  (nolock) 
						WHERE  b.compliance_name = 'Yes' and b.vultype = 'Vulnerability'
                               --AND b.vulseverity = 'Critical' 
                               --AND b.category = 'Operating System'
							   	and PublishDate > EOMONTH(getdate(),-14) --published in the 12 months
								and PublishDate <= EOMONTH(getdate(),-3) 
                        GROUP  BY b.computer_idn) prevyear 
	ON prevyear.computer_idn = C.computer_idn
			LEFT OUTER JOIN HKG002.LDHKG_Server_Core.dbo.IPG_Location loc
			on c.computer_idn = loc.computer_idn
			where c.deviceid != 'Unassigned' and displayname is not null) --end AP 
			) AS [a]
		where [a].displayname 
			not in (select displayname from OMA020.[LDGbl_Srv_Core].dbo.computer NOLOCK
			where scantype not like 'Unmanaged Device' and displayname is not null)
		) b
) AS c --END old c


left join ( select hostname, Domain, OU, CityID, SiteID, BrandID, OpCode  from omaedcapp249.shareddev.dbo.vw_adcomputersexpanded
			where  [Days Since Last Contact] < 60 and EnabledStatus = 'Enabled'
			) adx
on c.displayname = adx.hostname
)
