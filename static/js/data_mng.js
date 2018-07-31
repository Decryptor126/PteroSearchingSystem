$("#fileImport").click(function(){
    $("#files").click();
})
function fileImport(){//获取读取我文件的File对象
    var selectedFile = document.getElementById('files').files[0];
    var name = selectedFile.name;//读取选中文件的文件名
    var size = selectedFile.size;//读取选中文件的大小
    console.log("文件名:"+name+"大小:"+size);

    var reader = new FileReader();//这是核心,读取操作就是由它完成.
    reader.onload = function () {
        //当读取完成后回调这个函数,然后此时文件的内容存储到了result中,直接操作即可
        console.log(this.result);
    }
}

