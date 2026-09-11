<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="subestacao-teste" version="1.0"/>

  <Communication>
    <SubNetwork name="ProcessBus" type="8-MMS">
      <ConnectedAP iedName="SEL_351_1" apName="P1">
        <Address>
          <P type="IP">192.168.10.11</P>
          <P type="IP-SUBNET">255.255.255.0</P>
        </Address>
        <GSE ldInst="CFG" cbName="NewGOOSEMessage">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-03</P>
            <P type="APPID">0003</P>
            <P type="VLAN-ID">000</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </GSE>
        <SMV ldInst="CFG" cbName="SamplesMessage">
          <Address>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="APPID">4001</P>
            <P type="VLAN-ID">000</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </SMV>
      </ConnectedAP>

      <ConnectedAP iedName="SEL_351_2" apName="P1">
        <Address>
          <P type="IP">192.168.10.12</P>
          <P type="IP-SUBNET">255.255.255.0</P>
        </Address>
        <GSE ldInst="CFG" cbName="NewGOOSEMessage">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-04</P>
            <P type="APPID">0004</P>
            <P type="VLAN-ID">000</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </GSE>
      </ConnectedAP>
    </SubNetwork>
  </Communication>

  <IED name="SEL_351_1" type="Relay" manufacturer="SEL">
    <AccessPoint name="P1">
      <Server>
        <LDevice inst="CFG">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0Type">
            <DataSet name="three51to2411">
              <FCDA ldInst="CFG" lnClass="XCBR" lnInst="1" doName="Pos" fc="ST"/>
            </DataSet>
            <GSEControl name="NewGOOSEMessage" datSet="three51to2411" confRev="1"/>
            <SampledValueControl name="SamplesMessage" datSet="three51to2411" smvID="SEL_351_1_SV" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>

  <IED name="SEL_351_2" type="Relay" manufacturer="SEL">
    <AccessPoint name="P1">
      <Server>
        <LDevice inst="CFG">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0Type">
            <DataSet name="three51to2411">
              <FCDA ldInst="CFG" lnClass="XCBR" lnInst="1" doName="Pos" fc="ST"/>
            </DataSet>
            <GSEControl name="NewGOOSEMessage" datSet="three51to2411" confRev="1"/>
          </LN0>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
</SCL>
