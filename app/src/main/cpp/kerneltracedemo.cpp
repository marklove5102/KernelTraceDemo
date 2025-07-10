#include <jni.h>
#include <thread>
#include <linux/unistd.h>
#include <string>
#include "log.h"
#include "uprobe_trace_user.h"

#define MAX_VMA_NUM 10

char module_path[PATH_MAX];
static uint64_t module_base = 0;
unsigned long start_addrs[MAX_VMA_NUM];
unsigned long end_addrs[MAX_VMA_NUM];
unsigned long vma_base[MAX_VMA_NUM];
int vma_num=0;



//用于解析进程自身maps文件获取module_base，module_path以及相关可执行段地址信息的函数
//这个示例里so是没有加密代码段，并且so在maps文件中出现的第一段内存区域的起始地址就是其加载的基址
//在很多其他情况下并非如此，这个要看情况改变获取的方法
bool init_vma(){
    FILE *f;
    char buf[256];
    f = fopen("/proc/self/maps","r");
    bool flag = false;
    if(!f){
        return false;
    }
    while (fgets(buf,256,f)!=NULL){
        unsigned long tstart,tend,tbase;
        char permissions[5];
        int major,minor;
        unsigned long inode;
        char path[256];

        int fields = sscanf(buf,"%lx-%lx %4s %lx %x:%x %lu %s",&tstart,&tend,permissions,&tbase,&major,&minor,&inode,path);
        if(fields==8){
            if(strstr(path,"libkerneltracedemo.so")){
//                LOGD("start:%lx,end:%lx,permissions:%s,tbase:%lx\n",tstart,tend,permissions,tbase);
                if(!flag){
                    strcpy(module_path,path);
                    module_base = tstart;
                    flag = true;
                }
                if(permissions[2]=='x'){
                    start_addrs[vma_num] = tstart;
                    end_addrs[vma_num] = tend;
                    vma_base[vma_num] = tbase;
                    vma_num++;
                }
            }
        }

    }
    fclose(f);
    if(vma_num==0){
        return false;
    }
    return true;
}


__attribute__((noinline)) void test_kernel_trace(){
    LOGD("test_kernel_trace fun calling");
}

void test(){
    while (true){
        test_kernel_trace();
        sleep(1);
    }
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    if(!init_vma()){
        LOGE("can not parse maps files");
        return JNI_VERSION_1_6;
    }
    LOGD("success parse maps files");

    //为KernelTrace提供必要的初始信息
    set_target_uid(getuid());
    set_module_base(module_base);
    set_target_file(module_path);

    LOGD("module_base:%llx,module_path:%s",module_base,module_path);

    //hook前进行的一些准备
    unsigned long test_fun_addr = (unsigned long)test_kernel_trace;
    unsigned long test_fun_offset = test_fun_addr - module_base;
    unsigned long uprobe_offset = 0;
    for (int i=0;i<vma_num;i++){
        if(test_fun_addr>start_addrs[i] && test_fun_addr<end_addrs[i]){
            uprobe_offset = test_fun_addr-start_addrs[i]+vma_base[i];//获取uprobe offset要进行的运算
        }
    }

    char oins[4];
    memcpy(oins,(void *)test_kernel_trace,4);//获取被hook函数的第一条汇编指令
    LOGD("test_fun_offset:%lx,uprobe_offset:%lx",test_fun_offset,uprobe_offset);
    //如果so的相应汇编指令不是在so加载后才动态解密可直接设置fix_insn参数为NULL
    //set_fun_info(uprobe_offset,test_fun_offset,"test_kernel_trace",NULL);

    //不过最好还是直接读取汇编指令并传入
    set_fun_info(uprobe_offset,test_fun_offset,"test_kernel_trace",oins);//发送hook请求

    //启动测试线程开始测试
    std::thread test_thread(test);
    test_thread.detach();
    return JNI_VERSION_1_6;
}
