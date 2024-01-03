# Packet-Sniffer
A simple software to stream network packets from the network and analyse network
## Description

Packet-Sniffer is a software used to listen to netwrok adapters in order to get the packets comming from the network
The project is specially made for windows os.It is based on c++ and  lipcap.The Gui is made with Qt Creator.

## Getting Started

### Dependencies

You will need to install 

* Windows 10
* Qt Creator
* Winpcap 4.1.3  (can be found in the code above)
* WpdPack_4_1_2  (can be found in the code above)

### Installing

* The first version can be downloaded in this address https://drive.google.com/file/d/1l4qTYRaBW-t3FQZLum2Wcki_6Zf4RIiK/view


### Executing program

* How to run the program
* open the project file in Qt Creator
* Select the suitable Kit for building
* Make sure that you have installed Winpcap on windows and extracted WpdPack
* In the pro file, remove the inclusion of library files, as the folderpath where they are found(WpdPack) might have changed
* Includes te library files again in the project, Then compile and run it

## Help

In case you encounter any issue, do not hesitate to write us.


## Authors

Contributors names and contact info

RONEL TCHOULAYEU :Author [@jordanprog86] (https://the-mainthread-jordan.jimdosite.com/)

## Version History

* 1.0
    * Initial Release

## License

This project is licensed under the [NAME HERE] License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* [winpcap](http://www.winpcap.org/)

## How to contribute ?
* Create a new branch derived from the main branch
* Update and commit your changes
* Add the new version details in the readme file, from bottom to top
* Add your name in the contributor section
