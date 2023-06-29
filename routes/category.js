const express = require('express');
const connection = require('../connection');
const router = express.Router();

var auth = require('../services/authentication');
var checkRole = require('../services/checkRole');

router.post('/add', auth.authenticateToken, checkRole.checkRole, (req, res, next) => {

    let category = req.body;
    query = 'insert into category (name) values(?)';
    connection.query(query, [category.name], (error, results) => {
        if (!error) {
            return res.status(200).json({ message: 'Category Added Successfully' });
        } else return res.status(500).json(error);
    })
})

router.get("/get", auth.authenticateToken, (req, res) => {
    var query = "select *from category order by name"
    connection.query(query, (error, results) => {
        if (!error) {
            return res.status(200).json(results);
        } else return res.status(500).json(error);
    })
    return res.status(401);
})


router.patch('/update', auth.authenticateToken, checkRole.checkRole, (req, res, next) => {
    let product = req.body;
    var query = "update category set name=? where id=?";
    connection.query(query, [product.name, product.id], (error, results) => {
        if (!error) {
            if (results.affectedRows == 0) {
                return res.status(404).json({ message: 'Category id does not exist' })
            }
            return res.status(200).json({ message: 'Category Updated Successfully' })
        } else return res.status(500).json(error);
    })
})

router.delete('/delete/:id', auth.authenticateToken, checkRole.checkRole, (req, res, next) => {
    const id = req.params.id;
    var query = 'delete from category where id=?';
    connection.query(query, [id], (error, results) => {
        if (!error) {
            if (results.affectedRows == 0) {
                return res.status(401).json({ message: 'Category Does Not Exist' })
            }
            return res.status(200).json({ message: 'Category Successfully Deleted' });
        } else return res.status(500).json(error);
    })
})




module.exports = router;