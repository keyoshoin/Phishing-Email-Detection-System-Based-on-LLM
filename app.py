"""
Flask Web应用
提供邮件上传、检测和结果展示功能
"""
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import os
from pathlib import Path
import traceback

from config import SECRET_KEY, DEBUG, UPLOAD_FOLDER, MAX_CONTENT_LENGTH
from models.detector import get_detector

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
CORS(app)

# 获取检测器实例
detector = get_detector()


@app.route('/')
def index():
    """主页"""
    return render_template('index.html')


@app.route('/api/detect', methods=['POST'])
def detect_email():
    """检测邮件API"""
    try:
        # 获取邮件内容
        if request.is_json:
            data = request.get_json()
            email_content = data.get('email_content', '')
        else:
            email_content = request.form.get('email_content', '')
        
        if not email_content:
            return jsonify({
                'success': False,
                'error': '邮件内容不能为空'
            }), 400
        
        # 执行检测
        result = detector.detect(email_content)
        
        return jsonify({
            'success': True,
            'result': result
        })
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """上传文件API"""
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': '没有文件被上传'
            }), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': '文件名为空'
            }), 400
        
        # 读取文件内容
        content = file.read().decode('utf-8', errors='ignore')
        
        if not content:
            return jsonify({
                'success': False,
                'error': '文件内容为空'
            }), 400
        
        # 执行检测
        result = detector.detect(content)
        
        return jsonify({
            'success': True,
            'result': result,
            'filename': file.filename
        })
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/report', methods=['POST'])
def generate_report():
    """生成详细报告API"""
    try:
        data = request.get_json()
        email_content = data.get('email_content', '')
        
        if not email_content:
            return jsonify({
                'success': False,
                'error': '邮件内容不能为空'
            }), 400
        
        # 生成报告
        report = detector.generate_report(email_content)
        
        return jsonify({
            'success': True,
            'report': report
        })
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/batch_detect', methods=['POST'])
def batch_detect():
    """批量检测API"""
    try:
        data = request.get_json()
        emails = data.get('emails', [])
        
        if not emails:
            return jsonify({
                'success': False,
                'error': '邮件列表不能为空'
            }), 400
        
        # 批量检测
        results = detector.batch_detect(emails)
        
        return jsonify({
            'success': True,
            'results': results,
            'count': len(results)
        })
    
    except Exception as e:
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查API"""
    return jsonify({
        'status': 'ok',
        'model_trained': detector.model_trained
    })


@app.errorhandler(413)
def request_entity_too_large(error):
    """文件过大错误处理"""
    return jsonify({
        'success': False,
        'error': '文件过大，请上传小于16MB的文件'
    }), 413


@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({
        'success': False,
        'error': '页面不存在'
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    return jsonify({
        'success': False,
        'error': '服务器内部错误'
    }), 500


if __name__ == '__main__':
    # 确保上传文件夹存在
    Path(UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("钓鱼邮件检测系统启动中...")
    print("=" * 60)
    print(f"访问地址: http://localhost:5000")
    print(f"调试模式: {DEBUG}")
    print(f"模型状态: {'已训练' if detector.model_trained else '未训练（使用规则检测）'}")
    print("=" * 60)
    
    app.run(debug=DEBUG, host='0.0.0.0', port=5000)
