[![GitHub release](https://img.shields.io/github/release/qlenlen/android_kernel_samsung_sm8550)](https://GitHub.com/qlenlen/android_kernel_samsung_sm8550/releases/) 
[![Github all releases](https://img.shields.io/github/downloads/qlenlen/android_kernel_samsung_sm8550/total)](https://GitHub.com/qlenlen/android_kernel_samsung_sm8550/releases/)
### :zap: Features
- 基于三星官方源码补全专属驱动
- 定期合并AOSP上游改动与其他优化
- 集成Re:Kernel以提供更好的墓碑体验
- 更快速的lz4与鸿蒙lz4kd提供zram支持
- 集成SUSFS提供更强的反检测能力

### 🔖 Important Notice
- 使用TWRP或者 [kernel flasher](https://github.com/qlenlen/KernelFlasher/releases) 刷入
- GKI模式开机即可集成KSU激活root权限
- 若使用LKM模式则需自行修补init_boot
- 适配Apatch (自24.12.07的发行版开始)

### ⭐ OneDesign
- Feature extension for OneUI

### 📰 Kernel Source Guideline
1. Download stock source code from [Samsung Opensource](https://opensource.samsung.com/uploadSearch?searchValue=S918B)
2. Clone AOSP from [repo](https://github.com/aosp-mirror/kernel_common/tree/android13-5.15-lts)
3. Merge anything you like into the stock one
4. Compile and you get it

### Credit
- Source from AOSP
- Drivers from Samsung
- Refer to some commits from `samsung-sm8550`

### Support
![捐赠/打赏](/mm_reward_qrcode_1747375785433.png)