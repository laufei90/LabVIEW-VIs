<?xml version='1.0' encoding='UTF-8'?>
<Project Type="Project" LVVersion="19008000">
	<Item Name="My Computer" Type="My Computer">
		<Property Name="CCSymbols" Type="Str">OS,Win;CPU,x86;</Property>
		<Property Name="NI.SortType" Type="Int">3</Property>
		<Property Name="server.app.propertiesEnabled" Type="Bool">true</Property>
		<Property Name="server.control.propertiesEnabled" Type="Bool">true</Property>
		<Property Name="server.tcp.enabled" Type="Bool">false</Property>
		<Property Name="server.tcp.port" Type="Int">0</Property>
		<Property Name="server.tcp.serviceName" Type="Str">My Computer/VI Server</Property>
		<Property Name="server.tcp.serviceName.default" Type="Str">My Computer/VI Server</Property>
		<Property Name="server.vi.callsEnabled" Type="Bool">true</Property>
		<Property Name="server.vi.propertiesEnabled" Type="Bool">true</Property>
		<Property Name="specify.custom.address" Type="Bool">false</Property>
		<Item Name="Utilities" Type="Folder">
			<Item Name="control_packet_header_ethernet.ctl" Type="VI" URL="../control_packet_header_ethernet.ctl"/>
			<Item Name="control_packet_header_ip.ctl" Type="VI" URL="../control_packet_header_ip.ctl"/>
			<Item Name="Parse Packet.vi" Type="VI" URL="../Parse Packet.vi"/>
			<Item Name="timestamp.vi" Type="VI" URL="../timestamp.vi"/>
			<Item Name="protocol.vi" Type="VI" URL="../protocol.vi"/>
		</Item>
		<Item Name="lvwpcap.lvlib" Type="Library" URL="../lvwpcap.lvlib"/>
		<Item Name="Packet Sniffer Example.vi" Type="VI" URL="../Packet Sniffer Example.vi"/>
		<Item Name="Dependencies" Type="Dependencies"/>
		<Item Name="Build Specifications" Type="Build"/>
	</Item>
</Project>
