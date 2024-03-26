import struct,array,time,socket,dns.resolver,platform,os,threading
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QApplication, QWidget, QLabel, QLineEdit,  QTextEdit ,QGridLayout,QPushButton

def get_os():
    os = platform.system()
    if os == "Windows":
        return "n"
    else:
        return "c"


def checksum(packet):              #计算报文检验和
    if len(packet) & 1:    #填充字节数为偶数
        packet += b'\0'
    words = array.array('h', packet)
    sum = 0
    for word in words:
        sum += (word & 0xffff)
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    return (~sum) & 0xffff
def check_host_exists(hostname):#利用dns检验主机是否有效
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['223.5.5.5', '223.6.6.6']#设置DNS服务器
    try:
        answer = resolver.resolve(hostname, 'A')
        for record in answer:
            print(record.to_text())
    except dns.resolver.NXDOMAIN:
        return 0
    except dns.exception.DNSException as e:
        return 0
class OutputThread(QThread):
    update_signal = pyqtSignal(str)

    def __init__(self, text, delay):
        super().__init__()
        self.text = text
        self.delay = delay

    def run(self):
        for line in self.text.split('\n'):
            self.update_signal.emit(line)
            time.sleep(self.delay)
class ICMPApp(QWidget):
    answer = ""
    no=6648
    reachable=0
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Ping工具")

        self.ip_label = QLabel("请输入目的ip地址:")


        self.ip_textbox = QLineEdit()
        self.pingtimesGet_label = QLabel("发送ping命令次数:")
        self.pingtimesGet_textbox= QLineEdit()


        self.send_button = QPushButton("发送ping命令")
        self.send_button.clicked.connect(self.send_icmp_request)

        self.clear_button = QPushButton("清空输出框")
        self.clear_button.clicked.connect(self.clear_output)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)#设置为只读

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)

        self.findsub_button = QPushButton("寻找子网主机")
        self.findsub_button.clicked.connect(self.find_sub)#绑定事件

        self.timeout_label=QLabel("请输入超时时限:")
        self.timeout_button = QPushButton("不启用", self)
        self.timeout_button.setCheckable(True)  #设置按钮为可切换状态
        self.timeout_button.clicked.connect(self.timeout_button_clicked)#绑定按钮点击事件
        self.timeout_textbox= QLineEdit()

        self.sizeGet_label = QLabel("请输入可选数据部分长度:")
        self.sizeGet_textbox = QLineEdit()
        self.sizeGet_textbox.setFixedSize(80,20)
        self.sizebutton = QPushButton("不启用", self)
        self.sizebutton.setCheckable(True)  # 设置按钮为可切换状态
        self.sizebutton.clicked.connect(self.sizebutton_clicked)
        self.sizeGet_textbox.setFixedHeight(20)
        self.sizebutton.setFixedSize(80, 40)
        self.timeout_label.setFixedSize(80,40)
        self.timeout_textbox.setFixedSize(80,20)
        self.timeout_button.setFixedSize(80,40)


        layout = QGridLayout()
        layout.addWidget(self.ip_label,0,0,1,1)#设置部件坐标
        layout.addWidget(self.ip_textbox,1,0,1,1)
        layout.addWidget(self.pingtimesGet_label,2,0)
        layout.addWidget(self.pingtimesGet_textbox,3,0)
        layout.addWidget(self.send_button,4,0)
        layout.addWidget(self.clear_button,5,0)
        layout.addWidget(self.findsub_button,6,0)


        layout.addWidget(self.output_box,13,0)

        layout.addWidget(self.sizeGet_label, 0, 1)
        layout.addWidget(self.sizeGet_textbox,1,1)
        layout.addWidget(self.sizebutton,2,1)

        layout.addWidget(self.timeout_label,0,2)

        layout.addWidget(self.timeout_textbox,1,2)
        layout.addWidget(self.timeout_button,2,2)
        self.output_thread = None
        self.setLayout(layout)
    def start_output(self):
        self.output_thread = OutputThread(text=self.answer, delay=1)
        self.output_thread.update_signal.connect(self.update_output)
        self.output_thread.start()

    def update_output(self, line):
        self.output_box.append(line)
    def ping_subhost(self,ip_str):
        cmd = ["ping", "-{op}".format(op=get_os()),
               "1", ip_str]
        output = os.popen(" ".join(cmd)).readlines()
        for line in output:
            if str(line).upper().find("TTL") >= 0:
                self.output_box.append("主机: %s 在线" % ip_str)
                self.reachable += 1
                break

    def clear_output(self):
        self.output_box.clear()

    def timeout_button_clicked(self):
        if self.timeout_button.isChecked():
            num=self.timeout_textbox.text()
            if num.isdigit()==False:
                self.timeout_button.setCheckable(0)
                self.output_box.append("错误: 请输入一个数字")
                self.sizeGet_textbox.clear()
            self.timeout_button.setText("启用")
        else:
            self.timeout_button.setText("不启用")
    def check_ip(self,addip):#检测输入地址是否有效
        spl_ip=addip.split('.')
        print(spl_ip)
        for i in range(0,4):
            print(i)
            if spl_ip[i].isdigit():
                if int(spl_ip[i])>=0 and int(spl_ip[i])<=255:#是否为ip地址
                    continue
                else :
                    return False
            else:
                return False
        return True
    def sizebutton_clicked(self):
        if self.sizebutton.isChecked():
            num=self.sizeGet_textbox.text()
            if num.isdigit()==False:
                self.sizeGet_textbox.clear()
                self.output_box.append("错误：请输入一个正确的数字")
                self.sizebutton.setChecked(0)

            self.sizebutton.setText("启用")
        else:
            self.sizebutton.setText("不启用")

    def extract_domain(self,url):
        # 去除 "http://" 前缀
        if url.startswith("http://"):
            url = url[7:]
        if url.startswith("https://"):
            url = url[8:]
        # 去除末尾的 "/"
        if url.endswith("/"):
            url = url[:-1]
        # 提取域名部分
        return url
    def send_icmp_request(self):#ping函数

        ip = self.ip_textbox.text()#获得输入的ip地址
        if self.check_ip(ip) :#检验是否有效地址
            ch=1
        else :
            ip=self.extract_domain(ip)
            ch= check_host_exists(ip)#利用dns检验域名对应主机是否有效
        if ch==0:
            self.output_box.append(f"错误：请输入有效一个ip地址")#错误输出错误提示消息
            return
        pingtimesstr=self.pingtimesGet_textbox.text()
        if pingtimesstr.isdigit()==False :#获得发送ping命令的次数
            self.pingtimesGet_textbox.clear()
            self.output_box.append("错误：请输入一个数字")
            return
        pingtimes=int(self.pingtimesGet_textbox.text())
        self.sendping(ip,pingtimes)
        self.start_output()
        self.answer=''
    def sendping(self,desip,pingtimes):
        recvtot=0
        maxntime=-1
        minntime=10000000000
        totaltime=0
        for i in range(pingtimes):
            header = struct.pack('bbHHh', 8, 0, 0, self.no, 5)#类型，代码，校验和，标识符，序号并打包成字节流
            data = struct.pack('d', time.time())#将当前时间戳打包成字节流并当作数据部分
            if self.sizebutton.isChecked():                              #启用可选数据段长度
                desired_length=int(self.sizeGet_textbox.text())
                print(desired_length)
                if len(data) < desired_length:
                    padding_length = desired_length - len(data)
                    padding = b'\x00' * padding_length  # 使用空字节填充至需要的长度
                    data += padding

            timeout_time=1
            if self.timeout_button.isChecked():             #启用可选超时时限
                timeout_in=int(self.timeout_textbox.text())
                timeout_time=timeout_in/1000              #设置时间限制
            packet = header + data
            chkSum = checksum(packet)
            header = struct.pack('bbHHh', 8, 0, chkSum, self.no, 5)#类型，代码，校验和，标识符，序号
            packet = header + data
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))#通过套接字建立连接
            s.settimeout(timeout_time)
            try:
                t1 = time.time()
                s.sendto(packet, (desip, 0))
                r_data, r_addr = s.recvfrom(1024)
                t2 = time.time()

                resStr = f"\n收到来自{r_addr[0]}的回复, " + f"数据长度为{len(r_data)}字节, " + f"往返时间为{(t2 - t1) * 1000:.2f} ms"
                h1, h2, h3, h4, h5 = struct.unpack('bbHHh', r_data[20:28])
                headStr = f"\ttype={h1}, code={h2}, " + f"chksum={h3}, Id={h4}, SN={h5}"
                if h1 == 0:  # Echo Reply
                    self.answer=self.answer+(resStr)
                    self.answer=self.answer+(headStr)
                    recvtot=recvtot+1
                    minntime=min(minntime,(t2 - t1) * 1000)
                    maxntime=max(maxntime,(t2 - t1) * 1000)
                    totaltime=totaltime+(t2 - t1) * 1000
                else:
                    str=(f"请求{desip}超时\n")
                    self.answer=self.answer+(str)
            except socket.timeout:#如果超时
                str = (f"请求{desip}超时\n")
                self.answer=self.answer+str
            s.close()
            self.no=self.no+1
        lostpac=pingtimes-recvtot

        totalstr = f"\n{desip}的Ping统计信息：\n \t 数据包：已发送={pingtimes},已接受={recvtot},丢失={lostpac}({(lostpac/pingtimes)*100:.0f}%)"
        self.answer=self.answer+(totalstr)
        if recvtot != 0:
            total2str=f"往返行程的估计时间(以毫秒为单位):\n\t最短={minntime:.2f}ms,最长={maxntime:.2f}ms,平均={totaltime/recvtot:.2f}ms"
            self.answer=self.answer+(total2str)



    def find_sub(self):
        threads = []
        subnethost=[]
        ip_now = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
        ip_spl = ip_now.split('.')
        for i in range(1, 256):
            ip_spl[3] = str(i)
            subnetip = ".".join(ip_spl)
            subnethost.append(subnetip)
        for i in subnethost:
            thread = threading.Thread(target=self.ping_subhost, args=(i,))
            threads.append(thread)
        for i in threads:
            i.start()
        for i in threads:
            i.join()
        self.output_box.append('扫描到子网中存在%s台设备' % self.reachable)
        self.reachable=0

if __name__ == '__main__':
    app = QApplication([])
    icmp_app = ICMPApp()
    icmp_app.resize(1000,800)
    icmp_app.show()
    icon = QIcon("icon.png")
    icmp_app.setWindowIcon(icon)
    app.exec()