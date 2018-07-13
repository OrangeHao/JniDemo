#include <jni.h>
#include <string>
#include <android/log.h>

#define LOGE(...) __android_log_print(ANDROID_LOG_DEBUG, "czh" ,__VA_ARGS__) // 定义LOGE类型

// 花指令
std::string reverseString(std::string s) {
    int len = s.length();
    int mid = len / 2;
    for (int i = 0; i < mid; i++) {
        int t = len - i - 1;
        s[i] ^= s[t];
        s[t] ^= s[i];
        s[i] ^= s[t];
    }
    return s;
}


static jobject getApplication(JNIEnv *env) {
    jobject application = NULL;
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != NULL) {
        jmethodID currentApplication = env->GetStaticMethodID(
                activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplication != NULL) {
            application = env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
        } else {
            //           LOGE("Cannot find method: currentApplication() in ActivityThread.");
        }
        env->DeleteLocalRef(activity_thread_clz);
    } else {
//        LOGE("Cannot find class: android.app.ActivityThread");
    }

    return application;
}

//"签名的元数据，通过以下方法获得："
//"1. 通过命令：keytool -list -rfc -keystore your.keystore"
//"2. 并用BASE64 解密，转换成16进制"
const char *app_signature ="308202c1308201a9a003020102020477831657300d06092a864886f70d01010b05"
        "003011310f300d060355040313066f72616e6765301e170d3138303731333032333634325a170d343330373"
        "0373032333634325a3011310f300d060355040313066f72616e676530820122300d06092a864886f70d010101"
        "05000382010f003082010a0282010100b22c7f153e63699fffa528c9ecc17b7cb1b4243f7797b570f6ab8488a78"
        "4c230fe175471b3d771bef54061edb0dc0ba54437ae1ff7507f59f814190ef373956a6d991fa942e99c69b6c5883"
        "895b309f0cfabad7bc8405db8a66e500adc20e3df8330813ca0459587fd0f93b0690905e45ff05f9b28e3e33b1"
        "3c323595cd73fcd9e2e5682fa822c4ff12ec7450821633f308b5cbf28eb245f3accda1cae25a8ea89677ab5887"
        "23814fccaf55eac268da1b95c5a2e6c37bbf4d77f331203af892d93f0fe219f90791df685c7a0c18f0e021013c8"
        "1a3969bc0aa4f63a38fe12819513ee870f3149065dffcfb27880ec8092f34fa2e448699059c7d6c52847d1ddcb"
        "0203010001a321301f301d0603551d0e041604144673f1f6943b2b6bfb5dc9a6383979b705ef9af3300d06092a8"
        "64886f70d01010b0500038201010001a7612714f0d188aed0b8d6654a5250b7a08d334f10bc40843f1d17598ae"
        "2a1e6a24f6a9d09766d53de3f4348dd9500e9ae247a4a3b9ef15e2e2d8c51cb2e892f41b298d1ee8999aaf962a1"
        "f49fa4376c4e13de987770e6a25961725867718cf8f7b572ad0947f3f0aa502d5ee5ad3efab199e1e1d4770787c"
        "e0d8bcf82b7b08f660d3274901d5da6929e081d71b21c9447b055f42dcfe9e768a1cf00576e43018411681e4150"
        "bd222373bf060078becc1f9aee398424cd1fd74ee56654d21ae509cf49026d60fd8024fa84c35ccbac3b0fafbe7"
        "82d791e526e78c59e499f81e1af8191e5f2bde76636b182b4e94fc2433716adb3f8042f39a1d8ab2935567a";


//签名验证函数
bool sign_verify(JNIEnv *env) {
    jobject context_object=getApplication(env);

    jclass context_class = env->GetObjectClass(context_object);

    //context.getPackageManager()
    jmethodID methodId = env->GetMethodID(context_class, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    jobject package_manager_object = env->CallObjectMethod(context_object, methodId);
    if (package_manager_object == NULL) {
        LOGE("getPackageManager() Failed!");
        return false;
    }

    //context.getPackageName()
    methodId = env->GetMethodID(context_class, "getPackageName", "()Ljava/lang/String;");
    jstring package_name_string = (jstring)env->CallObjectMethod(context_object, methodId);
    if (package_name_string == NULL) {
        LOGE("getPackageName() Failed!");
        return false;
    }
    env->DeleteLocalRef(context_class);

    //PackageManager.getPackageInfo(Sting, int)
    jclass pack_manager_class = env->GetObjectClass(package_manager_object);
    methodId = env->GetMethodID(pack_manager_class, "getPackageInfo", "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    env->DeleteLocalRef(pack_manager_class);
    jobject package_info_object = env->CallObjectMethod(package_manager_object, methodId, package_name_string, 0x40);
    if (package_info_object == NULL) {
        LOGE("getPackageInfo() Failed!");
        return false;
    }
    env->DeleteLocalRef(package_manager_object);

    //PackageInfo.signatures[0]
    jclass package_info_class = env->GetObjectClass(package_info_object);
    jfieldID fieldId = env->GetFieldID(package_info_class, "signatures", "[Landroid/content/pm/Signature;");
    env->DeleteLocalRef(package_info_class);
    jobjectArray signature_object_array = (jobjectArray)env->GetObjectField(package_info_object, fieldId);
    if (signature_object_array == NULL) {
        LOGE("PackageInfo.signatures[] is null");
        return false;
    }
    jobject signature_object = env->GetObjectArrayElement(signature_object_array, 0);
    env->DeleteLocalRef(package_info_object);

    //获取签名
    jclass signature_class = env->GetObjectClass(signature_object);
    methodId = env->GetMethodID(signature_class, "toCharsString", "()Ljava/lang/String;");
    env->DeleteLocalRef(signature_class);
    jstring signature_jstirng = (jstring) env->CallObjectMethod(signature_object, methodId);

    const  char *sign=env->GetStringUTFChars(signature_jstirng,NULL);

    LOGE("sign:%s",sign);

    if (strcmp(sign,app_signature)==0)
    {
        LOGE("app签名验证通过");
        return true;
    }

    return false;
}

//extern "C"
//JNIEXPORT jstring JNICALL
//Java_com_orange_jnidemo_MainActivity_stringFromJNI(JNIEnv *env, jclass type, jobject context) {
//
//    return NULL;
//}

/**
 * 加载 so 文件的时候，会触发 OnLoad
 * 检测失败，返回 -1，App 就会 Crash
 */
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    LOGE("JNI_ONLOAD");
    if (vm->GetEnv((void **) (&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }
    LOGE("start checkSignature");
    if (sign_verify(env) != JNI_TRUE) {
        LOGE("signature failed");
        return -1;
    }

    return JNI_VERSION_1_6;
}
