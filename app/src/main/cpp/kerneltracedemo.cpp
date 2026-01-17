#include <jni.h>
#include <thread>
#include <linux/unistd.h>
#include <string>
#include "log.h"
#include "uprobe_trace_user.h"

#define MAX_VMA_NUM 10

char module_path[PATH_MAX];
char fix_module_path[PATH_MAX];
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
    int a=0,b=0;
    a = b+8;
    b = a+5;
    char test[200];
    snprintf(test,200,"%d %d",a,b);
    LOGD("test_kernel_trace fun calling,%s",test);
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

    strcpy(fix_module_path,module_path);//这里设置为原模块路径就是跟没设置一样，只是用于演示api的使用

    //为KernelTrace提供必要的初始信息
    trace_init_info *base_info = (trace_init_info*)malloc(sizeof(trace_init_info));
    base_info->module_base = module_base;
    base_info->uid = getuid();

    base_info->tfile_name = (char *)malloc(strlen(module_path) + 1);
    strcpy(base_info->tfile_name,module_path);

    base_info->fix_file_name = (char *)malloc(strlen(fix_module_path) + 1);
    strcpy(base_info->fix_file_name,fix_module_path);

    int sret = trace_init(base_info);

    LOGD("module_base:%llx,module_path:%s,fix_module_path:%s,sret:%d",module_base,module_path,fix_module_path,sret);

    //hook前进行的一些准备
    unsigned long test_fun_addr = (unsigned long)test_kernel_trace;
    unsigned long test_fun_offset = test_fun_addr - module_base;
    unsigned long uprobe_offset = 0;
    for (int i=0;i<vma_num;i++){
        if(test_fun_addr>start_addrs[i] && test_fun_addr<end_addrs[i]){
            uprobe_offset = test_fun_addr-start_addrs[i]+vma_base[i];//获取uprobe offset要进行的运算
        }
    }

    uprobe_item_info *uprobe_item = (uprobe_item_info*)malloc(sizeof(uprobe_item_info));
    uprobe_item->uprobe_offset = uprobe_offset;
    uprobe_item->fun_offset = test_fun_offset;
    uprobe_item->fun_name = (char *)malloc(strlen("test_kernel_trace") + 1);
    strcpy(uprobe_item->fun_name,"test_kernel_trace");
    set_fun_info(uprobe_item);//发送hook请求

    //启动测试线程开始测试
    std::thread test_thread(test);
    test_thread.detach();
    return JNI_VERSION_1_6;
}
