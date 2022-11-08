import { Request,Response, NextFunction } from "express"
import { User } from "../models/User";

export const Auth = {
    private : async (req:Request, res:Response, next:NextFunction) =>{
        let success = false;

        // fazer verificação de Auth
        if(req.headers.authorization){
            let hash: String = req.headers.authorization.substring(6);
            let decoded: String = Buffer.from(hash, 'base64').toString();
            let data : String[] = decoded.split(':');
            
            if(data.length === 2){
                let hasUser = await User.findOne({
                    where: {
                        email: data[0],
                        password: data[1]
                    }
                });

                if(hasUser){
                    success = true;
                }
            }
        }

        if(success){
            next();
        }else{
            res.status(403).json({error:"Não autorizado"})
        }
    }
}

