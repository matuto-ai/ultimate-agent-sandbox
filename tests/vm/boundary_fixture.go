// Synthetic Workstation for the no-NIC disposable VM; no Runtime or credentials.
package main

import (
 "encoding/json"
 "encoding/binary"
 "unsafe"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "os/signal"
 "path/filepath"
 "strconv"
 "strings"
 "syscall"
 "time"
)

func emit(value any) { if err:=json.NewEncoder(os.Stdout).Encode(value); err!=nil { panic(err) } }
func code(err error) string {
 if err==nil { return "OK" }
 for _, e:=range []struct{v error; n string}{{syscall.EINVAL,"EINVAL"},{syscall.EDQUOT,"EDQUOT"},{syscall.ENOSPC,"ENOSPC"},{syscall.EACCES,"EACCES"},{syscall.EPERM,"EPERM"},{syscall.EROFS,"EROFS"},{syscall.ENETUNREACH,"ENETUNREACH"},{syscall.ECONNREFUSED,"ECONNREFUSED"}} {
  if errors.Is(err,e.v) { return e.n }
 }
 if e,ok:=err.(net.Error);ok&&e.Timeout(){return "TIMEOUT"}
 return "OTHER"
}
func allowed(path string) bool {
 if path=="/state" { return true }
 if filepath.Clean(path)!=path { return false }
 for _,room:=range []string{"alpha","beta"}{for _,name:=range []string{"repository","workspace","checkouts","references"}{if path=="/mnt/uas-boundary/"+room+"/"+name{return true}}}
 return false
}
func quota(path, kind string) {
 if !allowed(path){panic("not a synthetic tree")}
 dir,err:=os.MkdirTemp(path,"quota-probe-");if err!=nil{emit(map[string]any{"error":code(err)});return}
 // Keep the owned probe directory until the harness proves sibling health.
 count:=0;written:=0
 if kind=="block" {
  file,e:=os.OpenFile(filepath.Join(dir,"bytes"),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);err=e
  if err==nil {
   block:=make([]byte,1024*1024)
   for written<16*1024*1024 { n,e:=file.Write(block);written+=n;err=e;if err==nil{err=file.Sync()};if err!=nil{break} }
   if e:=file.Close();err==nil{err=e}
  }
 }else{
  for count<256 {f,e:=os.OpenFile(filepath.Join(dir,strconv.Itoa(count)),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);err=e;if err!=nil{break};err=f.Close();if err!=nil{break};count++}
 }
 emit(map[string]any{"error":code(err),"bytes":written,"files":count,"uid":os.Geteuid(),"probe_path":dir})
}
func attributes(path string){
 if !allowed(path)&&path!="/mnt/uas-boundary/attribute-control"{panic("not a synthetic tree")}
 file,err:=os.Open(path);if err!=nil{panic(err)};defer file.Close()
 read:=func() []byte {value:=make([]byte,28);_,_,e:=syscall.Syscall(syscall.SYS_IOCTL,file.Fd(),0x801c581f,uintptr(unsafe.Pointer(&value[0])));if e!=0{panic(e)};return value}
 original:=read()
 attempt:=func(data []byte) string {_,_,e:=syscall.Syscall(syscall.SYS_IOCTL,file.Fd(),0x401c5820,uintptr(unsafe.Pointer(&data[0])));if e==0{return "OK"};return code(e)}
 inherit:=append([]byte(nil),original...);binary.LittleEndian.PutUint32(inherit,binary.LittleEndian.Uint32(inherit)&^uint32(0x200))
 project:=append([]byte(nil),original...);binary.LittleEndian.PutUint32(project[12:16],0)
 clearResult:=attempt(inherit);afterClear:=read();projectResult:=attempt(project);afterProject:=read()
 uidMap,e:=os.ReadFile("/proc/self/uid_map");if e!=nil{panic(e)}
 emit(map[string]any{"clear_inherit":clearResult,"change_project":projectResult,"initial_project":binary.LittleEndian.Uint32(original[12:16]),"after_clear_inherit":binary.LittleEndian.Uint32(afterClear)&0x200!=0,"after_change_project":binary.LittleEndian.Uint32(afterProject[12:16]),"uid":os.Geteuid(),"uid_map":strings.TrimSpace(string(uidMap))})
}
func observe(){
 result:=map[string]any{"uid":os.Geteuid(),"gid":os.Getegid()};files:=map[string]string{}
 for _,name:=range []string{"/proc/self/status","/proc/self/attr/current","/proc/self/uid_map","/proc/self/gid_map","/sys/fs/cgroup/memory.max","/sys/fs/cgroup/pids.max","/sys/fs/cgroup/cpu.max"}{v,e:=os.ReadFile(name);if e!=nil{panic(e)};if len(v)>65536{panic("oversize")};files[name]=strings.TrimSpace(string(v))};result["files"]=files;emit(result)
}
func main(){
 if len(os.Args)>1 {
  switch os.Args[1]{
  case "observe":observe();return
  case "attributes":if len(os.Args)!=3{panic("attribute args")};attributes(os.Args[2]);return
  case "connect":
   if len(os.Args)!=3{panic("connect args")};c,e:=net.DialTimeout("tcp",os.Args[2],time.Second);reply:="";if e==nil{defer c.Close();c.SetDeadline(time.Now().Add(time.Second));b:=make([]byte,64);n,er:=c.Read(b);e=er;reply=string(b[:n]);if e==io.EOF&&n>0{e=nil}};emit(map[string]any{"error":code(e),"reply":reply});return
  case "write-new":
   if len(os.Args)!=3||!allowed(os.Args[2]){panic("write-new args")};file,e:=os.CreateTemp(os.Args[2],"sibling-probe-");written:=0;if e==nil{defer os.Remove(file.Name());written,e=file.Write(make([]byte,65536));if e==nil{e=file.Sync()};if closeErr:=file.Close();e==nil{e=closeErr}};emit(map[string]any{"error":code(e),"bytes":written,"uid":os.Geteuid()});return
  case "write":
   if len(os.Args)!=3||!allowed(os.Args[2]){panic("write args")};p:=filepath.Join(os.Args[2],"fixture-data");e:=os.WriteFile(p,[]byte("uas-boundary-data\n"),0600);emit(map[string]any{"error":code(e),"path":p,"uid":os.Geteuid()});return
  case "quota-block","quota-inode":
   if len(os.Args)!=3{panic("quota args")};quota(os.Args[2],strings.TrimPrefix(os.Args[1],"quota-"));return
  default:panic("unknown fixture command")
  }
 }
 raw,_:=os.ReadFile("/state/starts");count,_:=strconv.Atoi(strings.TrimSpace(string(raw)));count++
 if err:=os.WriteFile("/state/starts",[]byte(strconv.Itoa(count)),0600);err!=nil{panic(err)}
 listener,err:=net.Listen("tcp",":5000");if err!=nil{panic(err)}
 fmt.Printf("uas-boundary start=%d uid=%d\n",count,os.Geteuid())
 signals:=make(chan os.Signal,1);signal.Notify(signals,syscall.SIGTERM,syscall.SIGINT)
 go func(){<-signals;listener.Close()}()
 for{conn,err:=listener.Accept();if err!=nil{return};conn.SetDeadline(time.Now().Add(time.Second));conn.Write([]byte("uas-boundary-ok\n"));conn.Close()}
}
