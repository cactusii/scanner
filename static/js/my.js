$(document).ready(function () {


    // 新建任务
    $(".task-create").click(function () {
        var name = $("#taskName").val();
        var target = $("#taskTarget").val();
        var port_type = $("#portType option:selected").val()
        if (name == "" || target == "" || port_type == "") {
            alert("必填字段不能为空");
            return
        }
        var data = {
            name: name,
            target: target,
            port_type: port_type
        }
        $.ajax({
            url: "/api/v1/tasks",
            data: data,
            type: "post",
            success: function (data) {
                $("#taskModal").modal("hide");
                if (data.status == 200) {
                    swal({
                        title: "添加成功!",
                        text: "任务添加成功，请刷新页面后查看",
                        icon: "success",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-primary"
                        }
                    })
                } else {
                    swal({
                        title: "添加失败!",
                        text: data.msg,
                        icon: "error",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-primary"
                        }
                    })
                }
            },
            error: function () {
                alert("异常！");
            }
        })
    });

    // 删除任务
    $(".task-list .btn-delete").click(function () {
        task_id = $(this).attr("data-target");
//        alert(task_name);
        $.ajax({
            url: "/api/v1/tasks?id=" + task_id,
            type: "delete",
            success: function (data) {
                swal({
                    title: "删除成功!",
                    text: "任务删除成功，请刷新页面后查看",
                    icon: "success",
                    button: {
                        text: "继续",
                        value: true,
                        visible: true,
                        className: "btn btn-primary"
                    }
                })
            },
            error: function () {
                alert("异常！");
            }
        })
    })




    $(".config-create").click(function () {
        var name = $("#configSelfAddName").val()
        var userid = $("#configSelfAddUserid").val();
        var password = $("#configSelfAddPassword").val(); // 没有加密
        if (name == "" || userid == "" || password == "") {
            alert("所有字段不能为空");
            return
        }
        var data = {
            name: name,
            userid: userid,
            password: password
        };
        $.ajax({
            url: "/api/v1/config",
            data: data,
            type: "post",
            dataType: "json",
            success: function (data) {
                $("#configModal").modal("hide");
                if (data.status == 200) {
                    swal({
                        title: "添加成功!",
                        text: data.msg,
                        icon: "success",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-primary"
                        }
                    })
                } else {
                    swal({
                        title: "error!",
                        text: data.msg,
                        icon: "error",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-danger"
                        }
                    })
                }

            },
            error: function () {
                alert("异常！");
            }
        })
    });

    $(".config-delete").click(function () {
        var id = $(this).attr("data-target");
        $.ajax({
            url: "/api/v1/config?id=" + id,
            type: "delete",
            dataType: "json",
            success: function (data) {
                if (data.status == 200) {
                    swal({
                        title: "删除成功",
                        text: "配置删除成功, 请刷新后查看",
                        icon: "success",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-primary"
                        }
                    })
                } else {
                    swal({
                        title: "删除失败",
                        text: data.msg,
                        icon: "error",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-danger"
                        }
                    })
                }

            },
            error: function () {
                alert("异常！");
            }
        })
    });


    $(".finger-create").click(function () {
        var name = $("#fingerName").val()
        var desc = $("#fingerDesc").val();
        var finger_print = $("#fingerPrint").val();
        if (name == "" || finger_print == "") {
            alert("必填字段不能为空");
            return
        }
        var data = {
            name: name,
            desc: desc,
            finger_print: finger_print
        };
        $.ajax({
            url: "/api/v1/finger",
            data: data,
            type: "post",
            dataType: "json",
            success: function (data) {
                $("#fingerModal").modal("hide");
                if (data.status == 200) {
                    swal({
                        title: "添加成功!",
                        text: "指纹已添加进数据库中, 请刷新后查看",
                        icon: "success",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-primary"
                        }
                    })
                } else {
                    swal({
                        title: "error!",
                        text: data.msg,
                        icon: "error",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-danger"
                        }
                    })
                }

            },
            error: function () {
                alert("异常！");
            }
        })
    });

    $(".finger-delete").click(function () {
        var id = $(this).attr("data-target");
        $.ajax({
            url: "/api/v1/finger?id=" + id,
            type: "delete",
            dataType: "json",
            success: function (data) {
                if (data.status == 200) {
                    swal({
                        title: "删除成功",
                        text: "指纹删除成功, 请刷新后查看",
                        icon: "success",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-primary"
                        }
                    })
                } else {
                    swal({
                        title: "删除失败",
                        text: data.msg,
                        icon: "error",
                        button: {
                            text: "继续",
                            value: true,
                            visible: true,
                            className: "btn btn-danger"
                        }
                    })
                }

            },
            error: function () {
                alert("异常！");
            }
        })
    });

});