var apacheChart = echarts.init(document.getElementById('apache-chart'));

// 指定图表的配置项和数据
var option = {
    tooltip: {},
    legend: {
        data: ['中间件类型']
    },
    series: [{
        name: '中间件类型',
        type: 'pie',
        radius: '50%', // 饼状图半径，可设为像素值或百分比
        data: [
            {value: 335, name: 'Apache'},
            {value: 310, name: 'Nginx'},
            {value: 234, name: 'Tomcat'},
            {value: 135, name: 'IIS'},
            {value: 548, name: '其他'}
        ]
    }]
};

// 使用刚指定的配置项和数据显示图表
apacheChart.setOption(option);