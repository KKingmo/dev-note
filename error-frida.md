### error code
```ts
export const bypass_frida_open = () => {
  let tag = bypass_frida_open.name;
  const openPtr = Module.getExportByName("libc.so", "open");
  const open = new NativeFunction(openPtr, "int", ["pointer", "int"]);

  let fakePath = "/data/local/tmp/maps";
  Interceptor.replace(
    openPtr,
    new NativeCallback(
      function (pathnameptr, flag) {
        // console.warn("flag", flag);
        // console.warn("pathnameptr", pathnameptr);
        let pathname = Memory.readUtf8String(pathnameptr);
        if (pathname.indexOf("maps") >= 0 && pathname.indexOf("proc") >= 0) {
          log.d(tag, "replace maps " + pathname);
          let filename = Memory.allocUtf8String(fakePath);
          log.d(tag, "replace maps over");
          return open(filename, flag);
        }
        if (pathname.indexOf("/su") != -1) {
          log.d(tag, "replace su");
          let filename = Memory.allocUtf8String("/xxx/su");
          return open(filename, flag);
        }
        let fd = open(pathnameptr, flag);
        return fd;
      },
      "int",
      ["pointer", "int"]
    )
  );
};
```

### package.json
```json
{
  "name": "script",
  "version": "1.0.0",
  "description": "script",
  "main": "index.js",
  "scripts": {
    "prepare": "npm run build",
    "spawn": "frida -U -f com.kingmo.app -l agent.js --debug --runtime=v8",
  },
  "keywords": [],
  "author": "",
  "license": "ISC",
  "devDependencies": {
    "@types/frida-gum": "^18.4.0",
    "@types/node": "^14.14.2",
    "dotenv": "^16.4.1",
    "frida-il2cpp-bridge": "^0.9.0",
    "typescript": "^5.3.3",
    "frida-compile": "^10.0.0"
  }
}
```

### error
```shell
Exception in thread Thread-1 (_run):
Traceback (most recent call last):[SM P610::com.kingmo.app ]->

    self.run()
  File "C:\Users\rnazi\anaconda3\envs\py3\lib\threading.py", line 953, in run
    self._target(*self._args, **self._kwargs)
  File "C:\Users\rnazi\anaconda3\envs\py3\lib\site-packages\frida_tools\reactor.py", line 70, in _run
    work()
  File "C:\Users\rnazi\anaconda3\envs\py3\lib\site-packages\frida_tools\_repl_magic.py", line 34, in <lambda>
    repl._reactor.schedule(lambda: repl._resume())
  File "C:\Users\rnazi\anaconda3\envs\py3\lib\site-packages\frida_tools\application.py", line 477, in _resume
    self._device.resume(self._spawned_pid)
  File "C:\Users\rnazi\anaconda3\envs\py3\lib\site-packages\frida\core.py", line 86, in wrapper
    return f(*args, **kwargs)
  File "C:\Users\rnazi\anaconda3\envs\py3\lib\site-packages\frida\core.py", line 986, in resume
    self._impl.resume(self._pid_of(target))
frida.ProcessNotFoundError: unable to find process with pid 29883
```
