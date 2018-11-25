Cash2 Nodejs Mining Pool
========================

https://pool1.cash2.org

## Usage

### Dependencies

#### Redis
`sudo add-apt-repository ppa:chris-lea/redis-server`  
`sudo apt-get update`  
`sudo apt-get install redis-server`  

#### Other Dependencies
`sudo apt-get install libssl-dev`  
`sudo apt-get install libboost-all-dev`

### Install
`git clone https://github.com/cash2/cash2-mining-pool.git pool`  
`cd pool`  
`npm update`

### Start Pool
`node init.js`

Front end website needs to be hosted. We recommend using Apache web server on the same machine as the pool.

Credits
---------

* [fancoder](//github.com/fancoder) - Developper on cryptonote-universal-pool project.
* [dvandal](//github.com/dvandal) - Developper on cryptonote-nodejs-pool project from which current project is forked.

License
-------
Released under the GNU General Public License v2

http://www.gnu.org/licenses/gpl-2.0.html
