#FlowStatsReport

Description:
  To collect the statistics information of each flow from switch. Currently, the stats information of flows collected from only one switch.
  
  I used two virtual machines to run these scripts. First VM for Mininet and second VM for Ryu which will help us to understand more about transmission in between switch and controller.

  Two python script files,
  
  1) BigDataTopo1.py - This file should be run on Mininet VM
  
  2) big_data_switch_13.py - This file should be run on Ryu controller VM.
  


  Steps to run the script:

  1) In Ryu VM, you have to run big_data_switch_13.py 
  
   sudo ryu-manager --verbose big_data_switch_13.py
   
      The statics report will be stored in filename BigDataFlowStats.log. It will be stored on ryu manager working directory or you can search that filename by using "find" command. If you want to store some other location then modify the source code and specify it.
      

  2) In Mininet VM, you have to run BigDataTopo1.py
  
       a) Open a Terminal and run script 
       
             $sudo ./BigDataTopo1.py 
             
       b) To open another Terminal and type the following commands
       
             $sudo ovs-vsctl set Bridge s1 protocols=OpenFlow13 
             
            * This command is used to set Openflow protocol version for switch s1. In this terminal you can check what are the flow entries configured on switch s1 by
            
            $sudo ovs-ofctl -O openflow13 dump-flows s1


Th log file fromat as follows,

1465735740.272067,1,1,a6:d3:f1:ef:f0:d0,fa:77:03:48:24:fc,10.0.0.1,10.0.0.3,5,1b2

The corresponding field name are TimeStamp, SwitchID, IngressPort, Dst.MAC, Src.MAC, Src.IP, Dst.IP, Packet Count, BytesCount.

