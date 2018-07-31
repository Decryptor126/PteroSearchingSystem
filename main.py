# !/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request
from config import DevConfig
from flask_sqlalchemy import SQLAlchemy
#from sqlalchemy import func
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length
from datetime import datetime
from hashlib import md5
from hashlib import sha256, sha3_256, shake_256, blake2s   #修改过后的版本
from random import randint
import random
import sqlite3
import SM2
from SM3 import Hash_sm3 as SM3
import traceback

from flask_wtf import Form
from flask_bootstrap import Bootstrap 

app = Flask(__name__)
app.config.from_object(DevConfig)
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
admin_name = "Clancy"

len_para = int(SM2.Fp / 4)

def SHA3(value):
    return sha3_256(value.encode('utf-8')).hexdigest()
    
def BLAKE2(value):
    return blake2s(value.encode('utf-8')).hexdigest()
    
def SHAKE(value):
    SHAKE_LENGTH = 32
    return shake_256(value.encode('utf-8')).hexdigest(SHAKE_LENGTH)

salt = 'BUHUIQIANDUAN'

class data_query(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255))
    # 绝密
    attribute1 = db.Column(db.String(255))
    verify_value1 = db.Column(db.VARCHAR(255))
    # 机密
    attribute2 = db.Column(db.String(255))
    verify_value2 = db.Column(db.VARCHAR(255))
    # 秘密
    attribute3 = db.Column(db.String(255))
    verify_value3 = db.Column(db.VARCHAR(255))
    # 公开
    attribute4 = db.Column(db.String(255))
    verify_value4 = db.Column(db.VARCHAR(255))
    
    node1 = db.Column(db.VARCHAR(255))
    node2 = db.Column(db.VARCHAR(255))
    node_root = db.Column(db.VARCHAR(255))
    
    
    def __init__(self, name, attr4, attr3 = "", attr2 = "", attr1 = ""):
        random.seed(datetime.now())
        self.name = name
        self.attribute1 = attr1 + '#' + str(randint(2**128,2**256)) # 在数据后加上128位到256位的随机数
        self.verify_value1 = md5(self.attribute1.encode(encoding='utf-8')).hexdigest() # 数据的hash散列值
        self.attribute2 = attr2 + '#' + str(randint(2**128,2**256))
        self.verify_value2 = md5(self.attribute2.encode(encoding='utf-8')).hexdigest()
        self.attribute3 = attr3 + '#' + str(randint(2**128,2**256))
        self.verify_value3 = md5(self.attribute3.encode(encoding='utf-8')).hexdigest()
        self.attribute4 = attr4 + '#' + str(randint(2**128,2**256))
        self.verify_value4 = md5(self.attribute4.encode(encoding='utf-8')).hexdigest()
        
        self.node1 = md5((self.verify_value1 + self.verify_value2).encode("utf-8")).hexdigest()
        self.node2 = md5((self.node1 + self.verify_value1).encode("utf-8")).hexdigest()
        self.node_root = md5((self.node2 + self.verify_value1).encode("utf-8")).hexdigest()
        
    def __repr__(self):
        return "<DATA '{}'>".format(self.name)
    
class query_input(Form):
    name = StringField('Name',validators=[DataRequired(),Length(max=255)])
    
def hasSqlInject(queryname):
    alert_flag = False
    inj_str = "'|and|exec|union|create|insert|select|delete|update|count|*|%|chr|mid|master|truncate|char|declare|xp_|or|--|+"
    queryname = queryname.lower().strip()
    inj_str_array = inj_str.split("|")
    for sql in inj_str_array:
        try:
            if queryname.index(sql)>-1:
                alert_flag = True
                break
        except:
            break
    return alert_flag


@app.route('/loginpage')
def loginpage():
    return render_template('login.html')

@app.route('/regpage')
def regpage():
    return render_template('reg.html')

#Unused function
@app.route('/profilepage')
def profilepage():
    return render_template('profile.html')

#Unused function
@app.route('/usermngpage')
def usermngpage():
    return render_template('user_mng.html')

#datamngpage用读取数据库的方式渲染页面
@app.route('/datamngpage',methods=['POST','GET'])
def datamngpage():
     # 连接数据库
    current_level = request.args.get("current_level")
    user_name = request.args.get("user_name")
    is_login = request.args.get("is_login")
    if current_level !="1":
        return render_template('home.html', current_level=current_level, user_name=user_name,is_login=is_login)
    db2 = sqlite3.connect('database.db')
    # 数据库游标cursor
    cursor = db2.cursor()
    try:
        sql_read = "SELECT company_name,\
	    legal_person_name,\
	    capital_amount,\
	    register_time,\
	    phone_number,\
	    mail_addr,\
	    addr FROM company_info"
        cursor.execute(sql_read)
        result_2d = cursor.fetchall()
        row_num = len(result_2d)
        return render_template('data_mng.html',result_2d=result_2d, row_num=row_num,current_level=current_level,user_name=user_name)
    except:
        return render_template('data_mng.html',result_2d=None, row_num=0,current_level=4,user_name="Tourist")


'''
                    node_root                     
                  /           \
                node1     attribute1               
              /       \
            node2     attribute2                  
          /       \
    attribute4    attribute3


    value1 = capital_amount
    value2 = register_time
    value3 = phone_number
    value4 = mail_addr

'''

#最高级别查询
@app.route('/query_1', methods=['POST','GET'])
def query_1():
    queryname = request.form.get("queryname").strip()
    is_login = request.args.get("is_login")
    user_name = request.args.get("user_name")
    #app.logger.debug(is_login)
    #app.logger.debug(user_name)
    if queryname == "" or queryname == None or hasSqlInject(queryname) == True:
        return render_template('home.html', current_level="1", user_name=user_name,is_login=is_login)
    
      # 连接数据库
    db2 = sqlite3.connect('database.db')
    # 数据库游标cursor
    cursor = db2.cursor()
    try:
        sql_search = "SELECT company_name,legal_person_name,capital_amount,\
            register_time,\
            phone_number,\
	        mail_addr,\
            node_root FROM company_info WHERE company_name like '%" + queryname+ "%' OR legal_person_name like '%"+queryname+"%';"
        cursor.execute(sql_search)
        results = cursor.fetchall()
        return render_template('query_1.html',results=results,results_len=len(results),current_level=1,user_name=user_name,is_login=is_login)
    except:
        return render_template('home.html', current_level="1", user_name=user_name,is_login=is_login)
    
@app.route('/query_2', methods=['POST','GET'])
def query_2():
    queryname = request.form.get("queryname").strip()
    is_login = request.args.get("is_login")
    user_name = request.args.get("user_name")
    if queryname == "" or queryname == None or hasSqlInject(queryname) == True:
        return render_template('home.html', current_level="2", user_name=user_name,is_login=is_login)
      # 连接数据库
    db2 = sqlite3.connect('database.db')
    # 数据库游标cursor
    cursor = db2.cursor()
    try:
        sql_search = "SELECT company_name,legal_person_name,capital_amount,\
            register_time,\
            phone_number,\
	        v_mail_addr,\
            node_root FROM company_info WHERE company_name like '%" + queryname+ "%' OR legal_person_name like '%"+queryname+"%';"
        cursor.execute(sql_search)
        results = cursor.fetchall()
        return render_template('query_2.html',results=results,results_len=len(results),current_level=2,user_name=user_name,is_login=is_login)
    except:
        return render_template('home.html', current_level="2", user_name=user_name,is_login=is_login)
    

    
@app.route('/query_3', methods=['POST','GET'])
def query_3():
    queryname = request.form.get("queryname").strip()
    is_login = request.args.get("is_login")
    user_name = request.args.get("user_name")
    if queryname == "" or queryname == None or hasSqlInject(queryname) == True:
        return render_template('home.html', current_level="3", user_name=user_name,is_login=is_login)
    #app.logger.debug(queryname)
      # 连接数据库
    db2 = sqlite3.connect('database.db')
    # 数据库游标cursor
    cursor = db2.cursor()
    try:
        sql_search = "SELECT company_name,legal_person_name,capital_amount,\
            register_time,\
	        v_mail_addr,\
            node2,\
            node_root FROM company_info WHERE company_name like '%" + queryname+ "%' OR legal_person_name like '%"+queryname+"%';"
        cursor.execute(sql_search)
        results = cursor.fetchall()
        return render_template('query_3.html',results=results,results_len=len(results),current_level=3,user_name=user_name,is_login=is_login)
    except:
        return render_template('home.html', current_level="3", user_name=user_name,is_login=is_login)
    

    
@app.route('/query_4', methods=['POST','GET'])
def query_4():
    queryname = request.form.get("queryname").strip()
    is_login = request.args.get("is_login")
    user_name = request.args.get("user_name")
    if queryname == "" or queryname == None or hasSqlInject(queryname) == True:
        return render_template('home.html', current_level="4", user_name=user_name,is_login=is_login)
    #app.logger.debug(queryname)
    #连接数据库
    db2 = sqlite3.connect('database.db')
    # 数据库游标cursor
    cursor = db2.cursor()
    try:
        sql_search = "SELECT company_name,legal_person_name,capital_amount,\
            node1,\
            node_root FROM company_info WHERE company_name like '%" + queryname+ "%' OR legal_person_name like '%"+queryname+"%';"
        cursor.execute(sql_search)
        results = cursor.fetchall()
        return render_template('query_4.html',results=results,results_len=len(results),current_level=4,user_name=user_name,is_login=is_login)
    except:
        return render_template('home.html', current_level="4", user_name=user_name,is_login=is_login)

#Obsoleted function
@app.route('/')
def mainpage(current_level=4,user_name="Tourist"):
    return render_template('home.html', current_level=current_level, user_name = user_name)

#@app.route('/query/<int:current_level>')
@app.route('/home',methods=['POST','GET'])
def querypage():
    current_level = request.args.get("current_level")
    user_name=request.args.get("user_name")
    is_login = request.args.get("is_login")
    return render_template('home.html', current_level=current_level, user_name=user_name,is_login=is_login)
    

# 获取登录参数及处理
@app.route('/login',methods=['POST','GET'])
def getLoginRequest():
    # 连接数据库
    db2 = sqlite3.connect('users_database.db')
    # 数据库游标cursor
    cursor = db2.cursor()

    # SQL 查询语句
    sql = "select user.user, password, private_key, user.level from user, private_key where user.user='%s'" % request.form.get('user')+" and user.user = private_key.user"
    cursor.execute(sql)
    result_all = cursor.fetchall()
    if(len(result_all)==0):
        return '用户名或密码不正确'
    else:
        results = result_all[0]
        '''
        解密函数Decrypt
        例子中privatekey为私钥 pwd为密文 解密后为16进制数据
        '''
        m = SM2.Decrypt(results[1], results[2], len_para)
        M = bytes.fromhex(m)
        if M.decode() == request.form.get('password'):
        # 提交到数据库执行
            return render_template('loginsuccess.html', current_level=results[3],user_name = results[0])
        else: 
            return '用户名或密码不正确'
            # 执行sql语句
      
       
    '''
    except:
        # 如果发生错误则回滚
        traceback.print_exc()
        db2.rollback()
    '''
  
# 注册界面
@app.route('/reg')
def register():
    return render_template('reg.html')


def SBSEncrypt(hash_string1,hash_string2,hash_string3,hash_string4):
    random.seed(datetime.now())
    value1 = SHAKE(SM3(SHA3(hash_string1 + salt)))
    value2 = SM3(SHAKE(BLAKE2(hash_string2 + salt)))
    value3 = BLAKE2(SHA3(SM3(hash_string3 + salt)))
    value4 = SHAKE(BLAKE2(SHA3(hash_string4 + salt)))

    node2 = SM3(SHA3(BLAKE2(value4 + value3)))
    node1 = BLAKE2(SHAKE(SM3(node2 + value2)))
    node_root = SHA3(BLAKE2(SHAKE(node1 + value1)))
    return value1,value2,value3,value4,node1,node2,node_root #返回远足

def writeTable(result_2d):
    # 连接数据库
    db2 = sqlite3.connect('database.db')
    # 数据库游标cursor
    cursor = db2.cursor()

    sql_delete = "DROP TABLE IF EXISTS company_info"
    cursor.execute(sql_delete)


    sql_create = "CREATE TABLE company_info\
    (company_name VARCHAR(80),\
	legal_person_name VARCHAR(256),\
	capital_amount VARCHAR(256),\
	register_time VARCHAR(256),\
	phone_number VARCHAR(256),\
	mail_addr VARCHAR(256),\
	addr VARCHAR(256),\
    v_capital_amount VARCHAR(256),\
    v_register_time VARCHAR(256),\
    v_phone_number VARCHAR(256),\
	v_mail_addr VARCHAR(256),\
    node1,\
    node2,\
    node_root,\
    PRIMARY KEY(company_name));"


    sql_insert= "INSERT INTO company_info(\
    company_name,\
    legal_person_name,\
    capital_amount,\
    register_time,\
    phone_number,\
    mail_addr,\
    addr,\
    v_capital_amount,\
    v_register_time,\
    v_phone_number,\
	v_mail_addr,\
    node1,\
    node2,\
    node_root\
    )VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?);"

    cursor.execute(sql_create)
    db2.commit()
    

    row_num = len(result_2d)
   
            
        
    random.seed(datetime.now())
    for i in range(0,row_num-1):
 
        
        result_2d[i][2] = result_2d[i][2]+'#'+str(randint(2**64,2**128))
        result_2d[i][3] = result_2d[i][3]+'#'+str(randint(2**64,2**128))
        result_2d[i][4] = result_2d[i][4]+'#'+str(randint(2**64,2**128))
        result_2d[i][5] = result_2d[i][5]+'#'+str(randint(2**64,2**128))
        result_2d[i][6] = result_2d[i][6]+'#'+str(randint(2**64,2**128))
        result_encrypted = SBSEncrypt(result_2d[i][2],result_2d[i][3],result_2d[i][4],result_2d[i][5])
        
        cursor.execute(sql_insert,(result_2d[i][0],result_2d[i][1],\
        result_2d[i][2],result_2d[i][3],\
        result_2d[i][4],result_2d[i][5],\
        result_2d[i][6],\
        result_encrypted[0],\
        result_encrypted[1],\
        result_encrypted[2],\
        result_encrypted[3],\
        result_encrypted[4],\
        result_encrypted[5],\
        result_encrypted[6],))
    db2.commit()
    cursor.close()
    db2.close()

	
@app.route('/csvupload', methods=['POST','GET'])
def csvupload():
    error = None
    if request.method == 'POST':
        result = request.form.get("csvcontent","")
        result_2d = []
        result_2d = result.split("+")
        i = 0

        result_title = result_2d[0].split(",")
        row_len = len(result_title)

        #app.logger.debug(result_title)
        for a in result_2d[1:]:
            result_2d[i] = a.split(",")

            i=i+1

        row_num = len(result_2d)
        writeTable(result_2d)
        
        #col_num = request.form.get("csvcolnum","")
        
        return render_template('data_mng.html',result_2d=result_2d, row_num=row_num)
    #result = request.form.get("csvcontent")
    #上传到数据库
    #col_num =request.form.to_dict().get('csvcolnum')
    
    #result_len = len(result)
    #count = 0 
    #while (count<result_len):
    #    result[count:cou]
    else:
        return render_template('data_mng.html',result_2d = "error",row_num=0)


# 获取注册请求及处理
@app.route('/registuser',methods=['POST','GET'])
def getRegisterRequest():
    # 连接数据库
    db2 = sqlite3.connect('users_database.db')

    # 数据库游标cursor
    cursor = db2.cursor()

    # 如果存在返回用户名已存在
    sql_if_exist = "select * from user where user = '%s'" % request.form.get('user')
    cursor.execute(sql_if_exist)

    if(len(cursor.fetchall())):
        return '用户名已存在'
    
    '''
    len_para是密钥长度/4 密钥长度Fp在SM2设置
    e、d、k为随机16进制数
    '''
    e = SM2.get_random_str(len_para)
    d = SM2.get_random_str(len_para)
    k = SM2.get_random_str(len_para)

    '''
    加密函数Encrypt
    例子中Pa为公钥由私钥d计算得到 Message为消息
    '''
    Pa = SM2.kG(int(d, 16), SM2.sm2_G, len_para)
    Encrypt_password = SM2.Encrypt(request.form.get('password'), Pa, len_para, 0)

    # SQL 插入语句
    sql_user = "INSERT INTO user(user, password, public_key, level) VALUES ('%s'" % request.form.get('user')+", '%s'" % Encrypt_password+", '%s'" % Pa+", '%s'" % request.form.get('level')+")"
    sql_private_key = "INSERT INTO private_key(user, private_key) VALUES ('%s'" % request.form.get('user')+", '%s'" % d+")"

    try:
        # 执行sql语句
        cursor.execute(sql_user)
        cursor.execute(sql_private_key)

        # 提交到数据库执行
        db2.commit()

        # 注册成功之后跳转到登录页面
        return render_template('login.html')

    except:
        # 抛出错误信息
        traceback.print_exc()

        # 如果发生错误则回滚
        db2.rollback()

        return '注册失败'

    # 关闭cursor
    cursor.close()

    # 关闭数据库连接
    db2.close()

def init_userdate():
    # 连接数据库
    init_connect = sqlite3.connect('users_database.db')

    # 数据库游标init_cursor
    init_cursor = init_connect.cursor()

    # 如果表user不存在则新建
    init_cursor.execute("CREATE TABLE IF NOT EXISTS user (user varchar(50) PRIMARY KEY not null, password varchar(300), public_key varchar(300), level varchar(3))")

    # 如果表private_key不存在则新建
    init_cursor.execute("CREATE TABLE IF NOT EXISTS private_key (user varchar(50) PRIMARY KEY not null, private_key varchar(300))")

    # 关闭init_cursor
    init_cursor.close()

    # 提交事务
    init_connect.commit()

    # 关闭connection
    init_connect.close()
    
if __name__ == '__main__':
    init_userdate()
    app.run(ssl_context = (
        "server/server-cert.pem",
        "server/server-key.pem"))
