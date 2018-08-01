# Krack

This is a simple demo of "Key Reinstallation Attacks".  For more information, please refer to https://papers.mathyvanhoef.com/ccs2017.pdf.  

## 
![Sketch map of Krack](https://github.com/zjd0112/krack/blob/master/picture/dataflow.png)
## Building from source
```sh
    cd build
    cmake ..
    make
```
## Run the demo
```sh
    ./AP "master_key" "ap_port"
    ./Adversary "ap_ip" "ap_port" "adv_port"
    ./Client "adv_ip" "adv_port" "master_key" "file_path" 
```

