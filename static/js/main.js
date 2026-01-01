// 全局变量
let currentResult = null;

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', function() {
    console.log('钓鱼邮件检测系统已加载');
    setupDragAndDrop();
});

// 切换标签页
function switchTab(tabName) {
    // 移除所有active类
    document.querySelectorAll('.tab-button').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    
    // 添加active类到选中的标签
    if (tabName === 'text') {
        document.querySelector('.tab-button:first-child').classList.add('active');
        document.getElementById('text-panel').classList.add('active');
    } else {
        document.querySelector('.tab-button:last-child').classList.add('active');
        document.getElementById('file-panel').classList.add('active');
    }
}

// 检测邮件
async function detectEmail() {
    const emailContent = document.getElementById('email-content').value.trim();
    
    if (!emailContent) {
        alert('请输入邮件内容');
        return;
    }
    
    // 显示加载动画
    showLoading();
    hideResult();
    
    try {
        const response = await fetch('/api/detect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email_content: emailContent
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentResult = data.result;
            displayResult(data.result);
        } else {
            alert('检测失败: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('网络错误，请稍后重试');
    } finally {
        hideLoading();
    }
}

// 文件选择处理
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        uploadFile(file);
    }
}

// 上传文件
async function uploadFile(file) {
    showLoading();
    hideResult();
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentResult = data.result;
            displayResult(data.result);
            alert('文件上传成功: ' + data.filename);
        } else {
            alert('上传失败: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('网络错误，请稍后重试');
    } finally {
        hideLoading();
    }
}

// 显示结果
function displayResult(result) {
    // 显示结果区域
    document.getElementById('result-section').style.display = 'block';
    
    // 显示评分
    const scoreValue = document.getElementById('score-value');
    const scoreCircle = document.getElementById('score-circle');
    scoreValue.textContent = result.risk_score;
    
    // 根据风险评分设置颜色
    let borderColor;
    if (result.risk_score >= 80) {
        borderColor = '#e74c3c'; // 红色
    } else if (result.risk_score >= 60) {
        borderColor = '#f39c12'; // 橙色
    } else if (result.risk_score >= 40) {
        borderColor = '#3498db'; // 蓝色
    } else {
        borderColor = '#27ae60'; // 绿色
    }
    scoreCircle.style.borderColor = borderColor;
    
    // 显示分类结果
    document.getElementById('classification').textContent = result.classification;
    document.getElementById('classification').style.color = result.is_phishing ? '#e74c3c' : '#27ae60';
    
    // 显示风险等级
    const riskLevelElement = document.getElementById('risk-level');
    riskLevelElement.textContent = result.risk_level;
    riskLevelElement.className = 'info-value risk-badge ' + result.risk_color;
    
    // 显示置信度
    document.getElementById('confidence').textContent = result.confidence + '%';
    
    // 显示风险点
    if (result.risk_points && result.risk_points.length > 0) {
        const riskPointsList = document.getElementById('risk-points-list');
        riskPointsList.innerHTML = '';
        result.risk_points.forEach(point => {
            const li = document.createElement('li');
            li.textContent = point;
            riskPointsList.appendChild(li);
        });
        document.getElementById('risk-points-card').style.display = 'block';
    } else {
        document.getElementById('risk-points-card').style.display = 'none';
    }
    
    // 显示建议
    if (result.suggestions && result.suggestions.length > 0) {
        const suggestionsList = document.getElementById('suggestions-list');
        suggestionsList.innerHTML = '';
        result.suggestions.forEach(suggestion => {
            const li = document.createElement('li');
            li.textContent = suggestion;
            suggestionsList.appendChild(li);
        });
        document.getElementById('suggestions-card').style.display = 'block';
    } else {
        document.getElementById('suggestions-card').style.display = 'none';
    }
    
    // 显示特征详情
    displayFeatures(result.features);

    // 显示攻击类型分析
    displayAttackAnalysis(result);

    // 滚动到结果区域
    document.getElementById('result-section').scrollIntoView({ behavior: 'smooth' });
}

// 显示特征详情
function displayFeatures(features) {
    const featuresGrid = document.getElementById('features-grid');
    featuresGrid.innerHTML = '';
    
    if (!features) return;
    
    const trad = features.traditional || {};
    
    // URL特征
    const urlFeats = trad.url || {};
    addFeatureItem(featuresGrid, 'URL数量', urlFeats.url_count || 0);
    addFeatureItem(featuresGrid, '可疑URL', urlFeats.suspicious_url_count || 0);
    if (urlFeats.has_ip_url) {
        addFeatureItem(featuresGrid, 'IP地址URL', '是');
    }
    
    // 关键词特征
    const keywordFeats = trad.keyword || {};
    addFeatureItem(featuresGrid, '钓鱼关键词', keywordFeats.phishing_keyword_count || 0);
    if (keywordFeats.has_urgent_language) {
        addFeatureItem(featuresGrid, '紧急语言', '是');
    }
    if (keywordFeats.has_personal_info_request) {
        addFeatureItem(featuresGrid, '要求个人信息', '是');
    }
    
    // HTML特征
    const htmlFeats = trad.html || {};
    if (htmlFeats.has_html) {
        addFeatureItem(featuresGrid, 'HTML标签数', htmlFeats.html_tag_count || 0);
        if (htmlFeats.form_count > 0) {
            addFeatureItem(featuresGrid, '表单数量', htmlFeats.form_count);
        }
        if (htmlFeats.hidden_elements > 0) {
            addFeatureItem(featuresGrid, '隐藏元素', htmlFeats.hidden_elements);
        }
    }
    
    // 文本特征
    const textFeats = trad.text || {};
    addFeatureItem(featuresGrid, '文本长度', textFeats.length + ' 字符');
    addFeatureItem(featuresGrid, '单词数', textFeats.word_count || 0);
}

// 添加特征项
function addFeatureItem(container, label, value) {
    const div = document.createElement('div');
    div.className = 'feature-item';
    div.innerHTML = `<strong>${label}:</strong> ${value}`;
    container.appendChild(div);
}

// 显示攻击类型分析
function displayAttackAnalysis(result) {
    // 攻击类型
    const attackTypes = result.attack_types || [];
    if (attackTypes.length > 0 && attackTypes[0] !== '正常邮件') {
        const attackTypeCard = document.getElementById('attack-type-card');
        const attackTypesDiv = document.getElementById('attack-types');
        attackTypesDiv.innerHTML = '';

        attackTypes.forEach(type => {
            const badge = document.createElement('span');
            badge.className = 'attack-badge';
            badge.textContent = type;
            attackTypesDiv.appendChild(badge);
        });

        attackTypeCard.style.display = 'block';
    } else {
        document.getElementById('attack-type-card').style.display = 'none';
    }

    // LLM生成检测
    const llmAttack = result.llm_attack || {};
    if (llmAttack.is_llm_generated) {
        const llmCard = document.getElementById('llm-card');
        const llmDetection = document.getElementById('llm-detection');
        llmDetection.innerHTML = '';

        addInfoItem(llmDetection, 'LLM生成可能性',
            llmAttack.llm_score > 0.8 ? '高' : llmAttack.llm_score > 0.6 ? '中' : '低',
            llmAttack.llm_score > 0.8 ? 'danger' : 'warning');
        addInfoItem(llmDetection, 'LLM评分', (llmAttack.llm_score * 100).toFixed(1) + '%');
        addInfoItem(llmDetection, '置信度', llmAttack.confidence.toFixed(1) + '%');

        if (llmAttack.evidence && llmAttack.evidence.length > 0) {
            const evidenceDiv = document.createElement('div');
            evidenceDiv.innerHTML = '<strong>检测到的特征:</strong><ul>';
            llmAttack.evidence.forEach(evidence => {
                evidenceDiv.innerHTML += `<li>${evidence}</li>`;
            });
            evidenceDiv.innerHTML += '</ul>';
            llmDetection.appendChild(evidenceDiv);
        }

        llmCard.style.display = 'block';
    } else {
        document.getElementById('llm-card').style.display = 'none';
    }

    // 混合攻击链检测
    const hybridAttack = result.hybrid_attack || {};
    if (hybridAttack.is_hybrid_attack) {
        const hybridCard = document.getElementById('hybrid-card');
        const hybridDetection = document.getElementById('hybrid-detection');
        hybridDetection.innerHTML = '';

        addInfoItem(hybridDetection, '混合攻击',
            hybridAttack.is_hybrid_attack ? '是' : '否',
            hybridAttack.is_hybrid_attack ? 'danger' : 'success');
        addInfoItem(hybridDetection, '攻击链完整度',
            hybridAttack.is_complete_chain ? '完整' : '不完整');
        addInfoItem(hybridDetection, '检测阶段数', hybridAttack.stage_count);
        addInfoItem(hybridDetection, '风险等级', hybridAttack.risk_level.toUpperCase());

        if (hybridAttack.stages_detected && hybridAttack.stages_detected.length > 0) {
            const stagesDiv = document.createElement('div');
            stagesDiv.innerHTML = '<strong>检测到的阶段:</strong>';
            hybridAttack.stages_detected.forEach(stage => {
                const stageTag = document.createElement('span');
                stageTag.className = 'stage-tag';
                stageTag.textContent = stage;
                stagesDiv.appendChild(stageTag);
            });
            hybridDetection.appendChild(stagesDiv);
        }

        hybridCard.style.display = 'block';
    } else {
        document.getElementById('hybrid-card').style.display = 'none';
    }
}

// 添加信息项
function addInfoItem(container, label, value, colorClass = '') {
    const div = document.createElement('div');
    div.className = 'info-item';
    if (colorClass) {
        div.innerHTML = `<span class="info-label">${label}:</span> <span class="info-value badge-${colorClass}">${value}</span>`;
    } else {
        div.innerHTML = `<span class="info-label">${label}:</span> <span class="info-value">${value}</span>`;
    }
    container.appendChild(div);
}

// 生成详细报告
async function generateReport() {
    const emailContent = document.getElementById('email-content').value.trim();
    
    if (!emailContent) {
        alert('请先进行检测');
        return;
    }
    
    showLoading();
    
    try {
        const response = await fetch('/api/report', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email_content: emailContent
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // 显示报告（可以在新窗口或模态框中显示）
            alert(data.report);
            // 或者下载为文件
            downloadReport(data.report);
        } else {
            alert('生成报告失败: ' + data.error);
        }
    } catch (error) {
        console.error('Error:', error);
        alert('网络错误，请稍后重试');
    } finally {
        hideLoading();
    }
}

// 下载报告
function downloadReport(report) {
    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '钓鱼邮件检测报告_' + new Date().getTime() + '.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// 加载示例邮件
function loadSample() {
    const sampleEmail = `Subject: URGENT: Your Account Will Be Suspended

Dear Valued Customer,

We have detected unusual activity on your account. Your account will be suspended within 24 hours unless you verify your identity immediately.

Click here to verify your account: http://suspicious-site.tk/verify?id=12345

Please provide the following information:
- Your password
- Credit card number
- Social security number

This is an urgent matter. Act now to avoid account suspension!

If you don't respond within 24 hours, your account will be permanently closed and you will lose access to all your data.

Best regards,
Security Team`;
    
    document.getElementById('email-content').value = sampleEmail;
    switchTab('text');
}

// 清空输入
function clearInput() {
    document.getElementById('email-content').value = '';
}

// 重置检测
function resetDetection() {
    hideResult();
    document.getElementById('email-content').value = '';
    currentResult = null;
}

// 显示加载动画
function showLoading() {
    document.getElementById('loading').style.display = 'block';
}

// 隐藏加载动画
function hideLoading() {
    document.getElementById('loading').style.display = 'none';
}

// 隐藏结果
function hideResult() {
    document.getElementById('result-section').style.display = 'none';
}

// 设置拖放功能
function setupDragAndDrop() {
    const uploadArea = document.getElementById('upload-area');
    
    if (!uploadArea) return;
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, preventDefaults, false);
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    ['dragenter', 'dragover'].forEach(eventName => {
        uploadArea.addEventListener(eventName, highlight, false);
    });
    
    ['dragleave', 'drop'].forEach(eventName => {
        uploadArea.addEventListener(eventName, unhighlight, false);
    });
    
    function highlight() {
        uploadArea.style.borderColor = '#3498db';
        uploadArea.style.background = 'rgba(52, 152, 219, 0.1)';
    }
    
    function unhighlight() {
        uploadArea.style.borderColor = '';
        uploadArea.style.background = '';
    }
    
    uploadArea.addEventListener('drop', handleDrop, false);
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length > 0) {
            uploadFile(files[0]);
        }
    }
}
